---
title: "Protected Process Light (PPL)"
date: 2026-08-24
permalink: /ppl/
tags: [ppl, protected-process, eprocess, kernel, windbg, defender]
summary: WinDbg notes — find EPROCESS.Protection and zero it.
---

# PPL

`OpenProcess` on Defender / lsass / csrss hits a second gate in `NtOpenProcess` (`PsGrantedAccess`): it compares the caller's `_EPROCESS.Protection` rank against the target's. Too low → `ACCESS_DENIED`. The field is one byte.

`.reload /f` if names do not resolve. LiveKD is read-only — `eb` needs a writable kernel debug session.

Offsets (`Protection`, `ActiveProcessLinks`, `ImageFileName`) are **build-specific**. Always run `dt nt!_EPROCESS` on the target to confirm them.

---

## Key Structure

```
_PS_PROTECTION  (1 byte, packed)
+0x000  Type    bits 0–2   0=None  1=PPL  2=PP
+0x000  Audit   bit 3      usually 0
+0x000  Signer  bits 4–7   trust rank
```

Byte value = `(Signer << 4) | Type`. Setting `Type = 0` disables protection regardless of Signer.

| Signer | Who | Byte |
|--------|-----|------|
| 0 | None | `0x00` |
| 3 | Antimalware | `0x31` (MsMpEng) |
| 4 | Lsa | `0x41` (lsass with RunAsPPL) |
| 6 | WinTcb | `0x62` (csrss PP) |

---

## 1. Get the offsets

```text
dt nt!_EPROCESS 0 Protection
```
Type-only read (`0` = no memory access). Returns the field offset, e.g. `+0x5FA` or `+0x6FA`. **Write this down.**

```text
dt nt!_EPROCESS 0 ActiveProcessLinks
dt nt!_EPROCESS 0 ImageFileName
```
`ImageFileName` is 15 chars — long names are truncated (`MpDefenderCoreService.exe` → `MpDefenderCore`).

---

## 2. Find the EPROCESS

**WinDbg shortcut:**
```text
!process 0 0 MsMpEng.exe
```
The address after `PROCESS` is the `_EPROCESS` pointer.

**Walk the process list (what the tool does internally):**
```text
dq nt!PsInitialSystemProcess L1
```
Dereferences the pointer → System `_EPROCESS` (the list head).

```text
? nt!PsInitialSystemProcess - nt
```
RVA of the symbol — stable per build.

For each process in the list:
```text
dt nt!_EPROCESS <ep> ImageFileName
dt nt!_PS_PROTECTION <ep>+<Protection_offset>
dq <ep>+<ActiveProcessLinks_offset> L1
```

`ActiveProcessLinks.Flink` points **into** the next `LIST_ENTRY`, not the `_EPROCESS` base. Subtract the `ActiveProcessLinks` offset to get the next EPROCESS:
```
next_ep = Flink - ActiveProcessLinks_offset
```
Stop when `next_ep` equals the System EPROCESS address.

---

## 3. Read the Protection byte

```text
dt nt!_PS_PROTECTION <ep>+<Protection_offset>
```
Decodes the packed byte into Type, Audit, Signer fields.

```text
db <ep>+<Protection_offset> L1
```
Raw byte. `0x31` = PPL Antimalware. `0x00` = not protected.

Note: `Protection` is often unaligned (e.g. offset ends in `...FA`). Use `db` for a single byte read — do not use `dd` on an unaligned address, as adjacent `_EPROCESS` fields share that DWORD.

---

## 4. Zero the byte

```text
eb <ep>+<Protection_offset> 0
```
`eb` = write one byte. Sets Type, Audit, and Signer all to 0. The process keeps running — only the open-access gate is removed.

```text
db <ep>+<Protection_offset> L1
```
Verify it reads back as `00`.

---

## Commands reference

| Cmd | Does |
|-----|------|
| `dt type 0 field` | get field offset without reading memory |
| `dt type addr field` | dump field at live address |
| `dq` / `db` | dump QWORDs / bytes (`L<n>` = item count) |
| `eb` | write one byte |
| `!process 0 0 name.exe` | find `_EPROCESS` by image name |
| `poi(addr)` | dereference pointer at addr |

Offsets are build-specific — always confirm with `dt` on the target before use.
