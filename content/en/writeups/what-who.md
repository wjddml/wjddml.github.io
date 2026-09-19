---
title: "What/Who — Reversing VM Bytecode Sealed in a Container"
date: 2026-09-18
tags: ["rev", "custom-vm", "crypto"]
categories: ["L3ak CTF 2026"]
summary: "Unpack a custom container format to extract VM bytecode, recover the ISA, and invert the six challenge questions."
translationKey: "what-who"
---

## Overview

Two files ship with the challenge.

```
whatwho     ELF 64-bit, x86-64, stripped
vault.wwc   data
```

Running it prints an instance seed and asks six questions. Answer all six and you get the flag.

The plan.

1. Confirm the ELF is a VM interpreter
2. Decrypt the `vault.wwc` container
3. Recover the ISA, write a disassembler
4. Invert the six questions
5. Clone the instance locally and verify

## 1. The ELF is an interpreter

Step through in gdb and you land in the same function no matter which question you're on. The top of `sub_1CF0` explains why.

```c
v13 = (char *)(v12 + 12 * v10);
v14 = *v13;
v15 = v13[1]; v16 = v13[2]; v17 = v13[3];
v18 = *(_QWORD *)(v13 + 4);
```

Fixed 12-byte instructions, a large opcode switch, eight registers (`v156[1..8]`), a stack pointer (`v157`), a program counter (`v167`). The verification logic is bytecode inside `vault.wwc`, and the ELF is the CPU that runs it.

Chasing this structure dynamically goes nowhere. Unpack the container first.

## 2. Decrypting vault.wwc

`sub_18C0` is the loader. A 64-byte header.

```
magic 0x1A0A0D4F48575789 | ver=3 | hdrsz=64 | n_insns | data_size | entry | key | code_seal | data_seal
```

Then `12*n` bytes of code and `data_size` bytes of data. Both segments are scrambled by `sub_1780`, a splitmix-style keystream over `(key, domain, index)` with a per-byte rotate and subtract. The two domain constants are ASCII.

`sub_1810` computes a checksum per segment. **That's the verification mechanism.** One wrong byte in the decrypt and the seal mismatches, so correctness is confirmed rather than assumed.

```
insn=262 data=762 entry=0 key=91e10da5c79e7b1d
code seal True  data seal True
```

Strings in the data segment are the question prompts.

```
data+0x0000  Question 1 - Did you remember the password?
data+0x002d  Question 2 - What is today's special?
data+0x0054  Question 3 - Which way now?
```

## 3. Recovering the ISA

This took the most time, because Hex-Rays rewrote the switch with offset arithmetic to compact the jump table.

```c
v23 = (unsigned __int8)(v14 + 115);
switch ((char)v23) { case 84: ... }

v19 = v14 - 37;
switch (v19) { case 0x1E: ... }
```

The `case` values on screen are not opcodes. Undo the bias with `case - 115 mod 256` for the first group and `case + 0x25` for the second. The two above are actually `0xE1` and `0x43`.

There are also two modes with separate opcode spaces. `0x0C` enters stack mode, `0xFA` returns to register mode, and both are only allowed when sp is zero.

The instructions that matter.

| opcode | meaning |
|---|---|
| `0x5F` | `INPUT r[A]`, fmt=B, max=C, prompt=data[imm] |
| `0x7B` | `SUBMIT imm` |
| `0xCA` | `r[A] = SEED` |
| `0x31` | `r[A] = KEY` |
| `0x43` | `flag = (r[A] == imm)` |
| `0xDD` | `flag = (r[A] == r[B])` |
| `0x2E` / `0xBC` | `JF` / `JT` |
| `0xE1` | `FLAG` |

INPUT's fmt is `0`=raw, `1`=hex8, `2`=hex16, `3`=hex32, `4`=dec.

Fixed width keeps the disassembler short.

```python
for pc in range(len(code)//12):
    op, A, B, C = code[12*pc:12*pc+4]
    imm = struct.unpack_from("<Q", code, 12*pc+4)[0]
```

262 instructions. The data segment loads at VM address `0x2000` and the input buffer is `0x800`. Find the six `SUBMIT`s and everything between them is one question.

## 4. Inverting the questions

**Q1** Four bytes packed big-endian, then `XOR → ROL32 → MUL → xorshift → ADD → ROR32`, compared against `0xFB5647DA`. Every step is a bijection on 32 bits, so the inverse is unique. Modular inverse for the multiply, fixpoint iteration for the xorshift.

```python
x = rol32(0xFB5647DA, 3)
x = (x - 0x7F4A7C15) & m32
y = x
for _ in range(4):
    y = x ^ (y >> 15)
x = (y * pow(0x045D9F3B, -1, 1 << 32)) & m32
answer = (ror32(x, 9) ^ 0xC13FA9A9).to_bytes(4, "big")
```

**Q2** A stack-mode block. Per byte, `ROL8((c ^ acc) + A[i], B[i]) ^ C[i] == D[i]`, with four 16-byte tables at `0xe9/0xf9/0x109/0x119`. `acc` starts at `0x5A` and chains forward, so peel it left to right.

**Q3** 102 characters. Movement deltas are `N=-17, E=+1, S=+17, W=-1`, and after each move `data[r2+0x2129]` must be 1. A 17×17 maze, start 18, goal 96.

There's a trap here. The only constraints are **exactly 102 steps** and **every cell walkable**, with no visited set. This isn't a shortest-path problem. It needs a DP over (cell, steps remaining), padding with back-and-forth when steps are left over.

**Q4 / Q5** Both start with `MOV r0, SEED`. Q4 is 137 rounds of splitmix with a decimal answer, Q5 is xorshift for `((seed>>9)&0x3ff)+0x500` rounds with a 16-character hex answer. Transcribe the loops.

**Q6** A 10-round Feistel. Round keys live at `0x250/0x2a0/0x2f0` and the target `(r2, r3)` derives from the seed and key. Unwind it in reverse.

```python
a, b = r2, r3
for i in range(9, -1, -1):
    a, b = b ^ F(a, i), a
```

## 5. The rolling key

This is why Q6 doesn't fall out of the seed alone.

`v173` starts as `mix(seed ^ 0x57484F5F57415443)`. That constant is `"WHO_WHAT"` little-endian. And it gets remixed on **every `SUBMIT`** using the raw string you just entered.

So Q6's target depends on the exact bytes of your Q1 through Q5 answers, casing included. Solve in order; there's no skipping ahead.

## 6. Cloning the instance

`main` checks an environment variable before falling back to `/dev/urandom`.

```c
v3 = getenv("WHATWHO_NONCE");
if (strlen(v3) == 16) { ... }
```

Feed it the `Instance seed:` value the remote printed and you get an identical instance locally.

```bash
WHATWHO_NONCE=8ad2b00c27513180 ./whatwho vault.wwc
```

Verify all six offline, then connect to the remote once.

## What caught us

- **The seed changes per connection.** Q1 through Q3 are static, Q4 through Q6 are seed-dependent. Pasting answers from a previous run failed at Q4.
- **Q5 must be lowercase hex.** The parser only accepts `a-f`, and even if it didn't, different casing would change the key hash and quietly break Q6.
- **Q4 rejects leading zeros.**

## Takeaway

A dispatch loop, fixed-width instructions, and a separate data file. When those three show up, the binary in front of you is a CPU rather than a program. Stop stepping and unpack the data.

And every operation in this challenge is invertible. Recover the formulas statically and the answers compute directly, with no brute force anywhere.

---

Full scripts: [ctf-writeups/2026-l3ak/what-who](https://github.com/wjddml/ctf-writeups/tree/main/2026-l3ak/what-who)
