---
title: "Kernel Callbacks"
date: 2026-08-22
permalink: /kernel-callbacks/
tags: [kernel, callbacks, windbg, livekd, windows, edr]
summary: WinDbg notes — all five kernel callback cases, every command explained.
---

# Kernel Callbacks

Drivers register for system events. Defender (`WdFilter.sys`) typically uses all five:

| # | API | Symbol | Event |
|---|-----|--------|-------|
| 1 | `PsSetCreateProcessNotifyRoutine(Ex)` | `PspCreateProcessNotifyRoutine` | process create/exit |
| 2 | `PsSetCreateThreadNotifyRoutine(Ex)` | `PspCreateThreadNotifyRoutine` | thread create/exit |
| 3 | `PsSetLoadImageNotifyRoutine(Ex)` | `PspLoadImageNotifyRoutine` | EXE/DLL/driver map |
| 4 | `ObRegisterCallbacks` | `_OBJECT_TYPE.CallbackList` | handle open on Process/Thread |
| 5 | `CmRegisterCallbackEx` | `CallbackListHead` | registry |

Cases 1–3: same shape (fixed 64-slot array). Cases 4–5: linked lists with different removal mechanics.

---

## Setup

```text
setx _NT_SYMBOL_PATH "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"
```
One-time. Caches symbols at `C:\Symbols`.

```text
livekd64.exe -w
```
`-w` = write mode. Without it, `ep`/`eb`/`eq` (removal steps) will fail.

```text
.reload /f
```
Force-load symbols. Run first if any `nt!...` name fails to resolve.

```text
lm m nt
```
Show the `ntoskrnl` module line — confirms symbols resolved.

```text
? nt
```
Prints the kernel base address. Note it down; all live addresses sit near it.

---

## Shared concept: EX_FAST_REF (Cases 1–3)

Each array slot is a pointer with a refcount packed into the low 4 bits. Strip it before reading the block.

```
_EX_CALLBACK_ROUTINE_BLOCK
+0x000  RundownProtect    sync (0x20 = active)
+0x008  Function          callback pointer
+0x010  Context           value from registration
```

To decode a slot value:
```text
block    = slot & 0xFFFFFFFFFFFFFFF0
function = *(block + 0x08)
```

---

## Case 1 — Process create

```text
dp nt!PspCreateProcessNotifyRoutine L40
```
Dump all 64 slots (`L40` = hex 0x40). Non-zero = occupied. Copy the left-column base address.

```text
dq (<raw_slot_value> & 0xfffffffffffffff0) L2
```
Strip EX_FAST_REF nibble → points to `_EX_CALLBACK_ROUTINE_BLOCK`. `L2` shows `+0x000` and `+0x008 Function`. Copy the Function value.

```text
lm a <function>
```
Which module owns that address — identifies the driver that registered (e.g. `WdFilter.sys`).

```text
? nt!PspCreateProcessNotifyRoutine - nt
```
RVA of the array symbol — stable per build, changes per boot due to KASLR.

```text
ep <array_base + slot*8> 0
```
`ep` = write 8 bytes (pointer). Zeroing a slot unregisters the callback; the kernel skips NULL slots.

**Walk all used slots in one command:**
```text
.for (r $t0 = 0; @$t0 < 64; r $t0 = @$t0 + 1) { r $t1 = poi(nt!PspCreateProcessNotifyRoutine + (@$t0 * 8)); .if (@$t1 != 0) { r $t2 = poi((@$t1 & 0xfffffffffffffff0) + 8); .printf "Slot %d: fn=%p  ", @$t0, @$t2; lm a @$t2 } }
```
`$t0` = slot index, `$t1` = raw slot value, `$t2` = decoded function. Prints only used slots with owner.

---

## Case 2 — Thread create

Identical to Case 1. Only the symbol changes.

```text
dp nt!PspCreateThreadNotifyRoutine L40
dq (<raw_slot_value> & 0xfffffffffffffff0) L2
lm a <function>
? nt!PspCreateThreadNotifyRoutine - nt
ep <array_base + slot*8> 0
```

---

## Case 3 — Image load

Identical to Case 1. Fires for every image map: EXE launch, DLL load, and kernel driver loads.

```text
dp nt!PspLoadImageNotifyRoutine L40
dq (<raw_slot_value> & 0xfffffffffffffff0) L2
lm a <function>
? nt!PspLoadImageNotifyRoutine - nt
ep <array_base + slot*8> 0
```

---

## Case 4 — Handle callbacks (`ObRegisterCallbacks`)

Linked list on the Process/Thread object types. **Do not unlink** — disable via the `Active` flag instead; the kernel frees these entries itself and expects the list intact.

```
_OBJECT_TYPE
+0x0C8  CallbackList      LIST_ENTRY head

CALLBACK_ENTRY_ITEM
+0x000  Flink / Blink
+0x010  Operations        1=create, 2=dup, 3=both
+0x014  Active            1=on, 0=off
+0x028  PreOperation      callback pointer
+0x030  PostOperation     or NULL
```

Empty list: `Flink == type_addr + 0xC8`.

```text
dp nt!ObTypeIndexTable L10
```
Dumps 16 type-object pointers. Index `[7]` = Process type, `[8]` = Thread type (stable on x64 Win10 — verify on target).

```text
dt nt!_OBJECT_TYPE <type_addr> CallbackList
```
Shows the `CallbackList` head at `+0x0C8`. If `Flink == type_addr+0xC8` → nothing registered. Otherwise `Flink` is the first node.

```text
dq <node> L7
```
Seven QWORDs = bytes `+0x00..+0x37`. Reveals: Flink (`+0x00`), Blink (`+0x08`), Operations (`+0x10`), Active (`+0x14`), PreOperation (`+0x28`), PostOperation (`+0x30`). Copy Flink (next node) and PreOperation.

```text
lm a <PreOperation>
```
Identifies the driver owning this callback.

```text
eb (<node> + 0x14) 0
```
`eb` = write one byte. Sets `Active` to 0 — kernel checks this before calling PreOperation. Write `1` to re-enable.

```text
db <node>+0x14 L1
```
Verify the byte read back as `00`. Then follow Flink to the next node. Stop when `Flink == type_addr+0xC8`.

---

## Case 5 — Registry (`CmRegisterCallbackEx`)

List anchored at `CallbackListHead`. No `Active` field — removal requires a real unlink.

```
_CMREG_CALLBACK
+0x000  Flink
+0x008  Blink
+0x028  Function          callback pointer
```
`+0x028` is hex = 40 decimal = QWORD index 5 (0-based).

```text
dq nt!CallbackListHead L2
```
`+0x000 Flink` = first node, `+0x008 Blink` = last node. If `Flink == head address` → nothing registered. Copy Flink as the first node.

```text
dq <node> L6
```
**Must use `L6`** — default range stops before `+0x28`, missing the Function field. Six QWORDs reach it.

```text
lm a <function>
```
Identifies the driver owning this callback.

**Unlink (two pointer fix-ups):**
```text
eq <PREV_Flink_addr>  <NEXT>
eq (<NEXT> + 0x08)    <PREV_Flink_addr>
```
`PREV_Flink_addr` = the address you read the previous Flink FROM (not the node itself). For the first node, PREV is `nt!CallbackListHead`. Stop when `Flink == head address`.

```text
dq <PREV_Flink_addr> L1
```
Verify it now skips the removed node. Continue from `NEXT`.

---

## Commands reference

| Cmd | Does |
|-----|------|
| `dp` / `dq` / `db` | dump pointers / QWORDs / bytes (`L<n>` = item count, hex) |
| `ep` / `eq` / `eb` | write pointer / QWORD / byte |
| `dt type addr field` | dump one struct field at address |
| `lm a <addr>` | module containing address |
| `poi(addr)` | dereference pointer at addr |
| `? expr` | evaluate expression (RVA math, kernel base) |
| `.for` / `.if` / `.printf` / `r $t0` | pseudo-registers + script loop |
| `.reload /f` | force symbol load |

Offsets are build-specific — always confirm with `dt` on the target.
