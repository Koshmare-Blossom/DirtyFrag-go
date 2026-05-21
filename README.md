# dirtyfrag-go

> Two bugs. One shell. No disk writes.

Go port of [dirtyfrag](https://github.com/V4bel/dirtyfrag) (CVE-2026-43284 / CVE-2026-43500).

## How it works (tl;dr)

The bug class is in the Linux kernel XFRM subsystem. When a file page is `splice()`d into a pipe and then into an ESP-encrypted socket, the kernel decrypts the ESP payload in-place - directly into the page-cache page of the source file. The file is read-only. The page cache is not.

dirtyfrag chains two independent bugs exploiting this primitive:

**CVE-2026-43284 - ESP/XFRM path**

Installs 48 XFRM transport-mode SAs via `NETLINK_XFRM`. Each SA encodes 4 bytes of shellcode payload in the `seq_hi` field of its ESN replay state. A `vmsplice` + `splice` chain triggers ESP in-place decryption for each SA, writing those 4 bytes into the `/usr/bin/su` page-cache entry. 48 triggers, 192 bytes written, no race condition.

**CVE-2026-43500 - RxRPC/rxkad path**

Brute-forces 3 PCBC(fcrypt) session keys offline that produce the target byte sequences when decrypted. Fires an `AF_RXRPC` socket trigger for each key to patch the root entry in `/etc/passwd` to `root::0:0` (nullok). `su -` then accepts an empty password.

Both paths run in a user + network namespace (`CLONE_NEWUSER | CLONE_NEWNET`) to avoid requiring `CAP_NET_ADMIN` on the host.

## Usage

```bash
go build -o dirtyfrag-go .
./dirtyfrag-go

# Force a specific path
./dirtyfrag-go --force-esp
./dirtyfrag-go --force-rxrpc

# Verbose output
./dirtyfrag-go -v
```

The binary tries the ESP path first. If `/usr/bin/su` is not patched after, it falls back to the RxRPC path (up to 3 retries). On success it drops into a root shell via a fresh PTY.

### Cleanup

The exploit only touches the page cache. The on-disk binaries and `/etc/passwd` are untouched. A reboot restores everything. To evict immediately without rebooting:

```bash
echo 1 | tee /proc/sys/vm/drop_caches
```

## Requirements

- Linux - unpatched kernel (see below)
- No external tools or prebuilt payloads - pure Go, single static binary
- Kernel modules: `esp4`, `esp6` (ESP path) and/or `rxrpc` (RxRPC path)

## Affected kernels

All kernels before the patches:
- CVE-2026-43284: https://lists.openwall.net/netdev/2026/05/06/112
- CVE-2026-43500: https://lists.openwall.net/netdev/2026/05/06/114

## Mitigation

```bash
rmmod esp4 esp6 rxrpc
printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
  > /etc/modprobe.d/dirtyfrag.conf
```

## Compared to the original

| | C (original) | **Go** |
|---|---|---|
| External dependencies | none | none |
| Single file | no | no |
| Static binary | yes | yes |
| RxRPC path | yes | yes |
| ESP path | yes | yes |
| Namespace isolation | `unshare()` | re-exec with `Cloneflags` |

Go's runtime is multi-threaded from the start, so `unshare(CLONE_NEWUSER)` is not allowed. The Go port re-execs itself as a child process with `SysProcAttr.Cloneflags` set, which calls `clone()` before the Go runtime initializes.

## References

- [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) - original C PoC
- [CVE-2026-43284 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-43284)
- [CVE-2026-43500 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-43500)

## Credits

- **V4bel** - vulnerability discovery and original PoC
