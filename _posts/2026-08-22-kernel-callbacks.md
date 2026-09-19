---
title: "Kernel Callbacks — How EDRs See Every Process, Thread, and Image"
date: 2026-08-22
categories: [Windows Internals, Kernel]
tags: [kernel, callbacks, windbg, windows, edr]
summary: WinDbg notes — enumerate and disable kernel callbacks.
---

# Kernel callback notes (WinDbg)

Drivers register for system events. Defender (`WdFilter.sys`) typically uses all five.

| API | Array / list | Event |
|-----|----------------|-------|
| `PsSetCreateProcessNotifyRoutineEx` | `PspCreateProcessNotifyRoutine` | process create/exit |
| `PsSetCreateThreadNotifyRoutineEx` | `PspCreateThreadNotifyRoutine` | thread create/exit |
| `PsSetLoadImageNotifyRoutineEx` | `PspLoadImageNotifyRoutine` | EXE/DLL map |
| `ObRegisterCallbacks` | `_OBJECT_TYPE.CallbackList` | handle open on Process/Thread |
| `CmRegisterCallbackEx` | `CallbackListHead` | registry |

`.reload /f` first if names do not resolve. LiveKD is read-only — `ep` / `eb` / `eq` need a writable kernel debug session.

**EX_FAST_REF (notify arrays only):** slot is pointer + refcount in the low 4 bits.

```
block    = slot & 0xFFFFFFFFFFFFFFF0
function = *(block + 0x08)
```

Same block for process, thread, and image notify:

```
_EX_CALLBACK_ROUTINE_BLOCK
+0x000  RundownProtect    sync (0x20 = active)
+0x008  Function          callback pointer  ← lm a this
+0x010  Context           value from registration
```

![types](/assets/images/callbacks-types-overview.svg)

---

## 1. Process / thread / image notify

64-slot arrays. Same steps; only the symbol changes.

### Dump

```
dp nt!PspCreateProcessNotifyRoutine
dp nt!PspCreateThreadNotifyRoutine
dp nt!PspLoadImageNotifyRoutine
```

`dp` = dump pointers. Non-zero = used slot. Zeros = empty. Save **array base** (left column of the first line). Slot `i` is at `base + i*8`.

### Decode one slot

```
dq (<raw_slot> & 0xfffffffffffffff0)
```

Mask low nibble → `_EX_CALLBACK_ROUTINE_BLOCK`. `+0x08` = function.

### Owner

```
lm a <function>
```

Which driver contains that address.

### RVA (for tools)

```
? nt!PspCreateProcessNotifyRoutine - nt
? nt!PspCreateThreadNotifyRoutine  - nt
? nt!PspLoadImageNotifyRoutine     - nt
```

KASLR moves the base; RVA stays for that build.

### Zero a slot

```
ep <array_base + index*8> 0
```

Kernel skips NULL slots.

### All used slots (first 14)

```
.for (r $t0 = 0; @$t0 < 14; r $t0 = @$t0 + 1) { r $t1 = poi(nt!PspCreateProcessNotifyRoutine + (@$t0 * 8)); .if (@$t1 != 0) { r $t2 = poi((@$t1 & 0xfffffffffffffff0) + 8); .printf "Slot %d: fn=%p\n", @$t0, @$t2; lm a @$t2 } }
```

Swap the symbol for thread/image.

![array chain](/assets/images/callbacks-array-chain.svg)

---

## 2. ObRegisterCallbacks (handles)

Linked list on Process (index 7) and Thread (index 8). Disable via **Active**, do not unlink.

```
_OBJECT_TYPE
+0x0C8  CallbackList      LIST_ENTRY head

CALLBACK_ENTRY_ITEM
+0x000  Flink / Blink
+0x010  Operations        1=create, 2=dup, 3=both
+0x014  Active            1=on, 0=off  ← eb this
+0x028  PreOperation      callback  ← lm a this
+0x030  PostOperation     or NULL
```

Empty list: `Flink == type_addr + 0xC8`.

### Type objects

```
dp nt!ObTypeIndexTable
```

`[7]` Process, `[8]` Thread.

### List empty?

```
dt nt!_OBJECT_TYPE <type_addr>
```

Look at `+0xC8 CallbackList`. Flink ≠ head → first node is that Flink.

### Dump node

```
dq <node> L7
lm a <PreOperation>
```

### Disable

```
eb (<node> + 0x14) 0
```

Kernel checks `Active` before `PreOperation`. Walk Flink until it equals `type_addr + 0xC8`.

![ob list](/assets/images/callbacks-ob-linked-list.svg)

---

## 3. Registry (`CmRegisterCallbackEx`)

List at `CallbackListHead`. **No Active field** — unlink the node.

```
_CMREG_CALLBACK
+0x000  Flink
+0x008  Blink
+0x028  Function          callback  ← lm a this
```

`+0x028` is **hex** = **40** decimal. Each pointer is 8 bytes, so QWORD index = `40 / 8` = **5** (0-based; the 6th QWORD, bytes 40–47). Not decimal 28.

Empty: `Flink == CallbackListHead`.

### Head

```
dq nt!CallbackListHead
```

### Node + owner

```
dq <node>
lm a <function>
```

### Unlink

```
eq <PREV>            <NEXT>
eq (<NEXT> + 0x08)   <PREV>
```

Walk Flink until it equals the head.

![cm unlink](/assets/images/callbacks-cm-unlink.svg)

---

## Commands

| Cmd | Does |
|-----|------|
| `dp` / `dq` | dump pointers / QWORDs |
| `ep` / `eb` / `eq` | edit pointer / byte / QWORD |
| `dt` | dump typed struct |
| `lm a` | module containing address |
| `poi(addr)` | read pointer at addr |

Offsets (`+0xC8`, `+0x28`, …) are build-specific — confirm with `dt` on the target.
