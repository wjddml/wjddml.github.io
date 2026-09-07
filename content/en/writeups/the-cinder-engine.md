---
title: "The Cinder Engine — Reversing a Custom VM Embedded in an ARM Binary"
date: 2026-09-06
tags: ["rev", "custom-vm", "firmware", "crypto", "arm"]
categories: ["Cyber Apocalypse 2026"]
summary: "Recover the ISA of a custom VM embedded in a stripped ARM aarch64 binary, then invert the 8-round SPN block cipher implemented inside its firmware to recover the flag."
translationKey: "cinder-engine"
---

## Overview

The challenge ships a single file, `cinder`.

```
$ file cinder
cinder: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, stripped
```

Run it and it reads a password, then prints nothing but true or false. aarch64, stripped, PIE — the first impression is intimidating, but none of the verification logic lives in the native code. A firmware image is embedded in the binary and `cinder` is the interpreter that runs it.

The plan:

1. Identify the VM interpreter in the native code, get the ROM base and size
2. Dump the firmware
3. Recover the ISA from the dispatch branches, write a disassembler
4. Classify the data regions inside the firmware
5. Extract the linear layer matrix
6. Invert 8 rounds to recover the password
7. Decrypt the flag with the password

Getting to the ISA was relatively smooth. Steps 4 through 6, reading the cipher back out of the disassembly, took most of the time.

## 1. Identifying the interpreter

If aarch64 is new to you, this is where you hesitate. The approach is no different from x86-64 ELF. Only the instruction set changes, and once a decompiler is attached the reading flow is the same. If anything, fixed 4-byte instructions and a generous register file make aarch64 decompile output tidier than x86.

Stripped means no symbols, so you look for structure instead. The interpreter body has a distinct shape: read four bytes, pack them into a 32-bit word, branch on one of those bytes through a large dispatch, and have every branch index the same global array.

Three globals fall out of the decompilation.

| Symbol | Role | Evidence |
|---|---|---|
| `DAT_00100e80` | ROM (firmware) | instruction fetch target |
| `DAT_00113018` | register file | 4-byte stride, nibble-indexed |
| `DAT_00113058` | RAM | byte stride, `& 0xffff` |

The register file and RAM are `0x40` apart. That is 4 bytes × 16 entries, so **sixteen 32-bit registers**. RAM is masked with `& 0xffff`, so **64KB**.

Everything step 2 needs is right here. The ROM base is at file offset `0xe80`, and the ROM access opcode carries this:

```c
// opcode 0xc6 (LDR_ROM)
reg[rd] = ROM[(imm16 + reg[rs1]) % 0x131e];
```

**The modulus is the firmware size.** No estimating, no working backwards from the data layout — `0x131e`, stated outright.

**Worth noting.** Because the binary is PIE, addresses shown by static analysis tools are offsets from the image base. Cross-referencing with dynamic analysis means adding the runtime base. Running an aarch64 binary on an x86 host needs `qemu-aarch64`.

```
$ qemu-aarch64 -L /usr/aarch64-linux-gnu ./cinder
```

## 2. Dumping the firmware

Both values come straight from step 1.

```python
FILE_PATH = 'the_cinder_engine/cinder'
OFFSET = 0xe80
SIZE = 0x131e

with open(FILE_PATH, 'rb') as f:
    f.seek(OFFSET)
    firmware_data = f.read(SIZE)

with open('firmware.bin', 'wb') as out:
    out.write(firmware_data)
```

## 3. Recovering the ISA

The bit manipulation in the fetch path spells out the instruction format.

```c
word = byte3 << 24 | byte2 << 16 | byte1 << 8 | byte0;

imm16 = word & 0xffff;
rd    = byte2 >> 4;
rs1   = byte2 & 0xf;
rs2   = byte0 & 0xf;
```

Fixed 4-byte instructions. Read as a little-endian 32-bit word, the layout is clean.

```
 31    24 23  20 19  16 15               0
+--------+------+------+------------------+
| opcode |  rd  | rs1  |      imm16       |
+--------+------+------+------------------+
                              rs2 = imm16 & 0xF
```

Two registers share a byte as nibbles, and three-operand instructions pull `rs2` back out of the low nibble of the immediate. Immediate-form and three-register-form instructions overlap on the same field.

Sign extension:

```c
imm16_s = (byte1 << 8) & 0x8000 ? (word | 0xffff0000) : imm16;
```

The branch target is `uVar2 + imm16_s`, and `uVar2` is already `pc + 4`. So it is **`pc + 4 + offset`**, not `pc + offset`. The PC increments as part of the fetch. That four-byte difference is an easy way to end up one instruction off on every branch.

### Opcode table

| opcode | mnemonic | operation |
|---|---|---|
| `0x00` | HALT | stop |
| `0x11` | MOV | `rd = rs1` |
| `0x29` | ROLI | `rd = rotl(rs1, imm & 31)` |
| `0x2a` | ROR | `rd = rotr(rs1, byte0 & 31)` |
| `0x2b` | SHL | `rd = rs1 << (byte0 & 31)` |
| `0x2c` | SHR | `rd = rs1 >> (byte0 & 31)` |
| `0x3a` | MOVI | `rd = imm16` |
| `0x52` | XOR | `rd = rs1 ^ rs2` |
| `0x53` | AND | `rd = rs1 & rs2` |
| `0x54` | OR | `rd = rs1 \| rs2` |
| `0x6b` | MUL | `rd = rs1 * rs2` |
| `0x7c` | ADD | `rd = rs1 + rs2` |
| `0x7d` | SUB | `rd = rs1 - rs2` |
| `0x80` | ADDI | `rd = rs1 + imm16` |
| `0x90` | CMP | `Z = (rs1 == rs2)` |
| `0xa0` | JMP | unconditional |
| `0xa1` | JZ | branch if `Z` |
| `0xa2` | JNZ | branch if not `Z` |
| `0xc4` | LDR | `rd = RAM[(rs1 + imm16) & 0xffff]` |
| `0xc5` | STR | `RAM[(rs1 + imm16) & 0xffff] = rd & 0xff` |
| `0xc6` | LDR_ROM | `rd = ROM[(rs1 + imm16) % 0x131e]` |
| `0xe0` | GETC | one input byte, sets `Z` on exhaustion |
| `0xe1` | PUTC | write `rs1 & 0xff` |

Opcodes cluster by high nibble, which speeds the table up. Once `0x29` turns out to be a rotate, `0x2a` through `0x2c` are worth assuming into the same family and then verifying.

The split between RAM and ROM access matters. Constant tables live in the same image as the code, and the S-box and round keys do in fact come from there.

### Three mistakes made during the CTF

The table below is the difference between the disassembler written during the competition and the actual behavior confirmed on review. All three went unnoticed at the time, and the solution still worked.

| Item | As written | Actual |
|---|---|---|
| `0x2a`–`0x2c` shift amount | `r{rs2}` | immediate `byte0 & 0x1f` |
| `0x29` rotate amount | `imm16_s` | `(-imm) & 0x1f` (effectively rotate left) |
| `0xa1` / `0xa2` | JNZ / JZ | JZ / JNZ |

For the shift family, `rs2 = byte0 & 0xf` and the shift amount `byte0 & 0x1f` overlap on the low four bits. Most instructions therefore print the same number either way, and only diverge when bit 4 is set. Not the kind of error that turns up by eye.

The branch polarity was fully inverted. The reason it did not matter surfaces in step 5: the linear layer, the one region that actually had to be read, contains no branches at all. Any region with control flow would have been traced backwards from end to end.

Passing the challenge and recovering the ISA correctly are separate things. Here, only the parts that mattered had to be right.

### What updates the flag

There is a single Z flag, but CMP is far from its only writer. ADD, SUB, AND, OR, XOR, MUL, and ADDI all update it based on whether the result is zero, and GETC sets it when input runs out. One arithmetic instruction slipped in front of a conditional branch changes its meaning, so the preceding instruction has to be read alongside it.

### Disassembler

```python
opcode   = byte3
reg_dest = (byte2 >> 4) & 0xF
reg_src1 =  byte2       & 0xF
reg_src2 =  byte0       & 0xF

imm16_u = (byte1 << 8) | byte0
imm16_s = imm16_u if not (imm16_u & 0x8000) else imm16_u - 0x10000

jmp_target = pc + 4 + imm16_s
```

## 4. Classifying the data regions

Find where the code ends in the disassembly and everything past it is data.

| Offset | Size | Contents |
|---|---|---|
| `0x0000` – | — | code (`0x0070`–`0x1018` is the linear layer) |
| `0x10c4` | 256 | S-box |
| `0x11c4` | 288 | round keys, 9 × 32 |
| `0x12e4` | 32 | target state |
| `0x1304` | 26 | encrypted flag |
| `0x131e` | | end |

The last region ends exactly at `0x131e`, matching the size from step 1. That is a decent sign nothing was missed.

The S-box is recognizable on sight: 256 bytes with no repeats. Nine round keys over a 32-byte state pins the structure down to an **8-round SPN**. Each round adds a key, substitutes through the S-box, and mixes through the linear layer. Same skeleton as AES with different parameters.

A target state baked into the firmware means the input gets encrypted and compared against it. Invert it and the required input falls out.

## 5. Extracting the linear layer matrix

This is where the approach forked.

The S-box and round keys are tables, so slicing them out is the whole job. The linear layer is not a table — it is code. Roughly 4KB from `0x0070` to `0x1018`, on the order of a thousand instructions.

You could read it instruction by instruction and track which input byte XORs into which output byte. But it is unrolled `LDR`/`XOR`/`STR` repetition, so transcription errors accumulate and there is no convenient way to tell whether you got it right.

Use the property of the transform instead. If each output byte is the XOR of some subset of input bytes, then flipping one input and watching which outputs change tells you exactly where that input contributes. Thirty-two runs give the entire 32×32 matrix.

```python
base_out = run_mix_block(rom, [0]*32)

mix_matrix = [[0] * 32 for _ in range(32)]
for i in range(32):
    test_in = [0] * 32
    test_in[i] = 1
    out = run_mix_block(rom, test_in)
    for j in range(32):
        mix_matrix[j][i] = out[j] ^ base_out[j]
```

`base_out` is measured separately for a reason. The layer is affine, not purely linear — a constant is folded in. Feeding the zero vector measures that constant first, and XORing it out of the rest leaves the linear part alone. Skip this and the matrix still looks plausible while the inversion quietly disagrees.

### Three opcodes are enough for the emulator

Probing requires executing that region. It does not require implementing the VM.

```python
def run_mix_block(rom, input_state):
    mem = [0] * 256
    for i in range(32):
        mem[i] = input_state[i]
    regs = [0] * 16

    pc = 0x0070
    while pc < 0x1018:
        b0, b1, b2, opcode = rom[pc:pc+4]
        imm = (b1 << 8) | b0

        if   opcode == 0xc4:   # LDR
            regs[(b2 >> 4) & 0xF] = mem[regs[b2 & 0xF] + imm]
        elif opcode == 0xc5:   # STR
            mem[regs[b2 & 0xF] + imm] = regs[(b2 >> 4) & 0xF]
        elif opcode == 0x52:   # XOR
            regs[(b2 >> 4) & 0xF] = regs[b2 & 0xF] ^ regs[b0 & 0xF]

        pc += 4
    return mem[128:160]
```

The real RAM is 64KB, but this region only touches input at 0–31 and output at 128–159, so 256 bytes covers it. Three opcodes, no branch handling, straight through from start to end.

That works on one condition: the region has to be fully unrolled straight-line code. A fixed 32-byte linear transform has no reason to loop, and the disassembly confirms there are no branches in that range.

**Check before running.** Grepping the region for `0xa0`–`0xa2` first is cheap insurance. One branch in there and this runner produces wrong output, silently.

Recovering the full ISA was not wasted work. Knowing that the region is straight-line and uses only three opcodes requires the disassembly. The runner, though, only needs to implement what actually executes.

## 6. Inverting

Invert the matrix over GF(2). With only 0 and 1 as elements, the subtraction in Gaussian elimination becomes XOR.

```python
def get_inverse_matrix(matrix):
    n = len(matrix)
    aug = [row[:] + [1 if i == j else 0 for j in range(n)]
           for i, row in enumerate(matrix)]

    for i in range(n):
        pivot = next((k for k in range(i, n) if aug[k][i] == 1), None)
        if pivot is None:
            sys.exit(1)
        aug[i], aug[pivot] = aug[pivot], aug[i]

        for k in range(n):
            if k != i and aug[k][i] == 1:
                for j in range(2*n):
                    aug[k][j] ^= aug[i][j]

    return [row[n:] for row in aug]
```

Bailing out on a missing pivot is deliberate. A singular matrix means the probing in step 5 was wrong. The linear layer of a working cipher is always invertible, so stopping here beats carrying a bad matrix forward.

Now unwind 8 rounds from the target state. The forward direction is `key XOR → S-box → linear layer`, so the inverse reverses that order.

```python
state = target[:]
for r in range(8, 0, -1):
    state = [state[i] ^ round_keys[r][i] for i in range(32)]
    state = [state[i] ^ base_out[i]      for i in range(32)]   # remove affine constant

    new_state = [0] * 32
    for i in range(32):
        for j in range(32):
            if inv_mix_matrix[i][j]:
                new_state[i] ^= state[j]

    state = [inv_sbox[b] for b in new_state]

required_input = [state[i] ^ round_keys[0][i] for i in range(32)]
```

Mind the round key indices. There are nine keys and eight rounds, because a key is added once more after the final round. The reverse direction therefore starts at `round_keys[8]` and finishes at `round_keys[0]`. Off by one and everything is wrong, with no intermediate check to tell you where.

## 7. Decrypting the flag

Feed the recovered 32 bytes back in and the check passes. That is not the flag.

A separate 26 bytes sit at `0x1304`, XORed with the password.

```python
enc_flag = list(rom[0x1304 : 0x1304 + 26])
flag = "".join(chr(required_input[i] ^ enc_flag[i]) for i in range(26))
```

Passing the check and obtaining the flag are deliberately split. Without having classified the data regions all the way to the end in step 4, this would have meant another round trip.

## Takeaways

- aarch64 is not far from x86-64 in tooling or approach. Stripped and PIE were the bigger variables.
- The interpreter body has the ROM base and size, register count, and RAM size all baked in as constants. Grabbing those before touching the firmware removes a lot of guesswork downstream.
- Recovering the ISA is not the finish line on a custom VM challenge. Most of the time here went into reading the cipher structure out of the recovered assembly.
- Unrolled linear code is faster and more reliable to observe than to read. Thirty-two executions produced the whole matrix.
- A partial emulator is often enough. Its premise — that the region is straight-line — does need checking.

---

Full scripts: [ctf-writeups/2026-cyber-apocalypse/the-cinder-engine](https://github.com/wjddml/ctf-writeups/tree/main/2026-cyber-apocalypse/the-cinder-engine)
