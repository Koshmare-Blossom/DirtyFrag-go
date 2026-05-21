package main

// AF_ALG helpers for pcbc(fcrypt) - used by the rxrpc path to compute
// csum_iv and the wire cksum without re-implementing PCBC in userspace.

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	afALG    = 38
	solALG   = 279
	algSetKey = 1
	algSetIV  = 2
	algSetOp  = 3
	algOpDecrypt = 0
	algOpEncrypt = 1

	rxrpcChannelMask = 3
	rxrpcCidShift    = 2
)

// sockaddrAlg mirrors struct sockaddr_alg from <linux/if_alg.h>:
//   __u16  salg_family   (2)
//   __u8   salg_type[14] (14)
//   __u32  salg_feat     (4)
//   __u32  salg_mask     (4)
//   __u8   salg_name[64] (64)
// total: 88 bytes
type sockaddrAlg struct {
	Family uint16
	Type   [14]byte
	Feat   uint32
	Mask   uint32
	Name   [64]byte
}

// afAlgIv mirrors struct af_alg_iv { __u32 ivlen; __u8 iv[]; }
// We use a fixed 8-byte IV for pcbc(fcrypt).
type afAlgIv8 struct {
	IVLen uint32
	IV    [8]byte
}

func algOpenPcbcFcrypt(key [8]byte) (int, error) {
	fd, _, errno := syscall.Syscall(syscall.SYS_SOCKET, afALG, syscall.SOCK_SEQPACKET, 0)
	if errno != 0 {
		return -1, fmt.Errorf("socket(AF_ALG): %w", errno)
	}
	s := int(fd)

	var sa sockaddrAlg
	sa.Family = afALG
	copy(sa.Type[:], "skcipher")
	copy(sa.Name[:], "pcbc(fcrypt)")

	_, _, errno = syscall.Syscall(syscall.SYS_BIND, uintptr(s),
		uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 {
		syscall.Close(s)
		return -1, fmt.Errorf("bind(AF_ALG pcbc(fcrypt)): %w", errno)
	}

	_, _, errno = syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s),
		solALG, algSetKey,
		uintptr(unsafe.Pointer(&key[0])), 8, 0)
	if errno != 0 {
		syscall.Close(s)
		return -1, fmt.Errorf("ALG_SET_KEY: %w", errno)
	}
	return s, nil
}

// algEncrypt runs a single PCBC(FCrypt) encryption with the given IV.
// Used for csum_iv and cksum computation per rxkad spec.
func algEncrypt(algFd int, iv [8]byte, in []byte) ([]byte, error) {
	opFd, _, errno := syscall.Syscall(syscall.SYS_ACCEPT, uintptr(algFd), 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("accept(AF_ALG): %w", errno)
	}
	fd := int(opFd)
	defer syscall.Close(fd)

	// Build control message: ALG_SET_OP + ALG_SET_IV
	// Must use CmsgSpace (aligned) for inter-cmsg offsets, CmsgLen for the len field.
	op := uint32(algOpEncrypt)
	ivStruct := afAlgIv8{IVLen: 8, IV: iv}

	opCmsgSpace := syscall.CmsgSpace(4)                              // space occupied by first cmsg
	ivCmsgSpace := syscall.CmsgSpace(int(unsafe.Sizeof(ivStruct)))   // space for second cmsg
	cbuf := make([]byte, opCmsgSpace+ivCmsgSpace)

	// First cmsg: ALG_SET_OP (data = uint32)
	hdr0 := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	hdr0.Level = solALG
	hdr0.Type = algSetOp
	hdr0.SetLen(syscall.CmsgLen(4))
	binary.LittleEndian.PutUint32(cbuf[syscall.SizeofCmsghdr:], op)

	// Second cmsg: ALG_SET_IV (data = af_alg_iv + 8-byte IV)
	hdr1 := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[opCmsgSpace]))
	hdr1.Level = solALG
	hdr1.Type = algSetIV
	hdr1.SetLen(syscall.CmsgLen(int(unsafe.Sizeof(ivStruct))))
	// Write IVLen then IV bytes directly into cmsg data area
	binary.LittleEndian.PutUint32(cbuf[opCmsgSpace+syscall.SizeofCmsghdr:], 8)
	copy(cbuf[opCmsgSpace+syscall.SizeofCmsghdr+4:], iv[:])

	iov := syscall.Iovec{Base: &in[0], Len: uint64(len(in))}
	msg := syscall.Msghdr{
		Control:    &cbuf[0],
		Controllen: uint64(len(cbuf)),
		Iov:        &iov,
		Iovlen:     1,
	}
	_, _, errno = syscall.Syscall(syscall.SYS_SENDMSG, uintptr(fd),
		uintptr(unsafe.Pointer(&msg)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("AF_ALG sendmsg: %w", errno)
	}

	out := make([]byte, len(in))
	n, err := syscall.Read(fd, out)
	if err != nil || n != len(in) {
		return nil, fmt.Errorf("AF_ALG read got %d want %d: %v", n, len(in), err)
	}
	return out, nil
}

// computeCsumIv implements rxkad_prime_packet_security():
//   tmpbuf[0..3] = {epoch, cid, 0, sec_ix} (big-endian, 16 bytes total)
//   PCBC-encrypt(tmpbuf, IV=session_key) → csum_iv = out[8..15]
func computeCsumIv(epoch, cid, secIx uint32, key [8]byte) ([8]byte, error) {
	s, err := algOpenPcbcFcrypt(key)
	if err != nil {
		return [8]byte{}, err
	}
	defer syscall.Close(s)

	in := make([]byte, 16)
	binary.BigEndian.PutUint32(in[0:], epoch)
	binary.BigEndian.PutUint32(in[4:], cid)
	binary.BigEndian.PutUint32(in[8:], 0)
	binary.BigEndian.PutUint32(in[12:], secIx)

	out, err := algEncrypt(s, key, in) // IV = session key itself
	if err != nil {
		return [8]byte{}, err
	}
	var csumIv [8]byte
	copy(csumIv[:], out[8:16])
	return csumIv, nil
}

// computeCksum implements rxkad_secure_packet():
//   x = (cid_low2 << 30) | (seq & 0x3fffffff)
//   buf = {htonl(callId), htonl(x)} (8 bytes)
//   PCBC-encrypt(buf, IV=csum_iv) → y = ntohl(enc[4:8])
//   cksum = (y >> 16) & 0xffff; if zero → 1
func computeCksum(cid, callID, seq uint32, key, csumIv [8]byte) (uint16, error) {
	s, err := algOpenPcbcFcrypt(key)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(s)

	x := (cid & rxrpcChannelMask) << (32 - rxrpcCidShift)
	x |= seq & 0x3fffffff

	in := make([]byte, 8)
	binary.BigEndian.PutUint32(in[0:], callID)
	binary.BigEndian.PutUint32(in[4:], x)

	out, err := algEncrypt(s, csumIv, in)
	if err != nil {
		return 0, err
	}
	y := binary.BigEndian.Uint32(out[4:8])
	v := uint16((y >> 16) & 0xffff)
	if v == 0 {
		v = 1
	}
	return v, nil
}
