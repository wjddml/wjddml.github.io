---
title: "After the Trigger — The x86-64 Minimum for Kernel Exploitation"
date: 2026-11-11
tags: ["kernel", "x86-64", "exploitation", "iretq", "kpti", "smep", "smap"]
categories: ["x86-64"]
summary: "The bug fired and now you have to get back to ring 3. This collects only what the CPU demands in that stretch — registers, structures, instructions. No techniques, no allocator."
translationKey: "kernel-x86-minimum"
---

Kernel exploitation material mostly comes in two kinds: how to trigger the bug, and how to groom the allocator. But in practice the place you get stuck is neither of those — it is **what comes after**. You have control, and now: how do you get back to ring 3, why does it die right after the return, and why does the same code look like it hangs in some environments.

That stretch isn't the domain of Linux data structures. It is the domain of the CPU interface. Reading kernel source won't show it; it lives where the Intel SDM says "satisfy these conditions." This post collects only those conditions.

There's one fact worth starting from. The top five slots of Linux's `struct pt_regs` have **exactly the same layout** as the stack frame `iretq` expects. What the kernel pushes on the way in and what it pops on the way out are the same shape, and most of this post follows from that.

## 1. Registers

### CS — privilege is two bits here

CPL is not a separate register. **The low two bits of the current CS selector** are the privilege level, directly. The CPU-side definition of "privilege escalation" in kernel exploitation is: get those two bits back to 3 while making the rest of the state consistent.

Linux x86-64 uses only four values. They are not constants to bake into an exploit — treat the list as a reference for reading a register dump and telling which side you are on.

```
__KERNEL_CS   0x10      index 2, RPL 0
__KERNEL_DS   0x18      index 3, RPL 0
__USER_DS     0x2b      index 5, RPL 3
__USER_CS     0x33      index 6, RPL 3
```

`0x33 = (6 << 3) | 3`. The upper bits are the GDT index, the low two are the RPL.

The CS descriptor also carries an L bit, which separates 64-bit mode from compatibility mode. That's why CS isn't merely a two-bit privilege field. But the CS you return with isn't a constant you pick — it's the value you saved before going in and hand back verbatim, so in practice the L bit rarely comes up again.

### SS — must be paired with CS

`iretq` checks that SS's RPL matches the CPL you are returning to. Put `0x33` in CS and leave a kernel value in SS and the return itself ends in `#GP`. Always set the two together.

DS and ES have their base and limit ignored in 64-bit mode, so there is effectively nothing to manage. FS and GS are the exception — those two carry a base of their own, via MSRs.

### RFLAGS — forget IF and it looks like a hang

If the RFLAGS you put in the return frame has IF (interrupt enable) cleared, you return to user code correctly, but no timer interrupt ever arrives again. It presents as a **stall**, not a crash, which makes it annoying to track down.

So exploits almost always save their own RFLAGS before going in and restore it verbatim.

The AC bit (bit 18) is worth knowing too. With that bit set, SMAP checks pass. Executing `stac` in ring 0, or controlling RFLAGS wholesale, effectively disables SMAP.

### Control registers — you can't read them, but you need to know them

There is no way to read these from userland. You still need to know which bit blocks what, because it determines your choice of technique.

```
CR0.WP    bit 16    write protect. clear it and .rodata becomes writable
CR3                 page table root. the heart of working around KPTI
CR4.PCIDE bit 17    PCID. there for KPTI's performance, so mind the bits when touching CR3
CR4.SMEP  bit 20    ring 0 may not execute user pages
CR4.SMAP  bit 21    ring 0 may not access user pages
```

The classic trick of clearing SMEP and SMAP through CR4 mostly fails on modern kernels: `native_write_cr4` checks pinned bits and puts them back. Executing `mov cr4` directly still works, but the path that goes through a kernel function is closed.

### MSRs — the entry point is written here

```
IA32_LSTAR          0xc0000082    syscall entry RIP
IA32_STAR           0xc0000081    CS and SS that syscall loads
IA32_FMASK          0xc0000084    RFLAGS bits syscall clears on entry
IA32_GS_BASE        0xc0000101    current GS base
IA32_KERNEL_GS_BASE 0xc0000102    the counterpart swapgs exchanges with
```

Overwriting `IA32_LSTAR` is syscall hooking, and the two GS bases are the two sides of `swapgs`. The kernel points GS base at its per-cpu area; userland uses FS for TLS. **That asymmetry is the cause of a debugging trap that shows up later.**

## 2. Memory and structures

### The iretq frame — five slots, this order

This is the standard path from ring 0 back to user. Starting at whatever RSP points to when `iretq` executes:

```
rsp + 0x00    RIP        user code to return to
rsp + 0x08    CS         the user CS you saved
rsp + 0x10    RFLAGS     the value you saved, IF included
rsp + 0x18    RSP        user stack
rsp + 0x20    SS         the user SS you saved
```

In 64-bit mode, `iretq` **always pops all five**, whether or not the privilege level changes. There is no 32-bit-era behavior where RSP and SS are skipped on a same-privilege return.

If memorizing the order is a nuisance, remember that it matches what the kernel pushes on the way in.

### pt_regs — attacker values sit on the kernel stack as-is

When you enter the kernel via syscall or interrupt, the entry code pushes the user registers onto the top of the kernel stack in a fixed layout. From low address upward:

```
r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax
rip cs eflags rsp ss
```

The last five are the `iretq` frame we just saw.

The first sixteen matter more. **All of them are values the user chose, and they land at a known offset on the kernel stack.** Put what you want in each register, make a syscall, and those values are laid out on the kernel stack. It is data you obtain without any leak, and it works directly as stack-pivot material.

The location is `task->stack + THREAD_SIZE - sizeof(struct pt_regs)`. This is the point where the transition mechanism itself becomes an attack resource; the RetSpill paper systematized this property.

### TSS — RSP0 and IST

The long-mode TSS is not for task switching. It holds two things.

```
RSP0        stack to load when entering ring 0 via interrupt or exception
IST[1..7]   stacks specific vectors are forced to use (NMI, #DF, #DB, ...)
```

One distinction splits off here. **Interrupts and exceptions switch stacks via TSS.RSP0, but `syscall` does not switch stacks at all.** `syscall` leaves RSP untouched and merely throws RIP at `IA32_LSTAR`. Loading the kernel stack is software work the entry code does by hand, out of per-cpu.

Overwrite TSS.RSP0 and the next interrupt uses an attacker-chosen address as its kernel stack.

### Page table bits — three are enough

```
bit 0     P      present
bit 2     U/S    1 means user-accessible
bit 63    NX     no execute
```

The U/S bit is what SMEP and SMAP judge on. Try to execute a U/S=1 page from ring 0 and SMEP stops you; try to read or write one and SMAP does. Both surface as `#PF`.

## 3. Instructions

```
syscall     RCX <- RIP, R11 <- RFLAGS, RIP <- LSTAR, CS/SS <- STAR,
            RFLAGS &= ~FMASK.  leaves RSP alone
sysretq     RIP <- RCX, RFLAGS <- R11.  too constrained to be common in exploits
iretq       pops the five slots above and returns.  the standard path
swapgs      IA32_GS_BASE <-> IA32_KERNEL_GS_BASE.  exactly once per boundary
stac/clac   set and clear RFLAGS.AC.  the SMAP bypass itself
mov crN     swap CR3 (KPTI), touch CR4 (SMEP/SMAP)
rdmsr/wrmsr LSTAR hooking, GS base manipulation
rdgsbase    with CR4.FSGSBASE on, userland can touch GS base too
pushfq/popfq save and restore user RFLAGS
```

Return code comes down to these two lines.

```asm
swapgs
iretq
```

With KPTI enabled, those two lines are not enough. User addresses are not mapped in the kernel CR3, so you fault immediately after `iretq`. Either swap CR3 yourself, or borrow the return trampoline the kernel already has: `swapgs_restore_regs_and_return_to_usermode`.

The trampoline opens with a run of `pop`s, so entering at the symbol address consumes too much stack. Skip that run and enter at `mov %rsp, %rdi`.

Reading what the code does from that point gives you the frame directly. It moves the old RSP into `%rdi`, reads seven slots relative to it and re-pushes them onto a fresh stack, switches CR3 to the user side, then does `pop %rdi` and `pop %rsp` and goes to `iretq`. So the stack at entry has to look like this:

```
+0x00   RDI      slot the trampoline pops
+0x08   RAX      same
+0x10   RIP
+0x18   CS
+0x20   RFLAGS
+0x28   RSP
+0x30   SS
```

Those first two slots are what the "two dummies" recipe actually refers to. They aren't discarded padding — they are the slots the trampoline restores into `%rdi` and `%rax`. The values don't matter only because user code overwrites both right after the return.

The entry offset varies with the kernel build, so don't write it down as a constant. Take the symbol address, disassemble it yourself, and measure the distance to `mov %rsp, %rdi`.

```bash
grep swapgs_restore_regs_and_return_to_usermode /proc/kallsyms
```

```
(gdb) x/40i <symbol address>
```

Keep the measured distance as a single constant on the exploit side; when the kernel changes, that's the only value you re-measure.

## 4. Where it dies when you get it wrong

The table that eats the most time in practice.

| Mistake | Symptom |
|---|---|
| CS isn't the user CS | `#GP` at `iretq`. Or CPL stays 0 and user code runs in ring 0 until it faults on its first access |
| SS not paired with CS | `#GP` at `iretq` |
| RFLAGS.IF left clear | Return succeeds. Then no interrupts arrive and it **looks like a stall** |
| Five slots out of order | `#GP`, or a jump to a bogus RIP and an unexplainable crash |
| `swapgs` omitted | **Does not die immediately.** User TLS is FS, so things look fine for a while; it dies oddly once library code touches GS |
| `swapgs` done twice | The kernel per-cpu pointer is left in user GS, and the next kernel entry uses a garbage base |
| Bare `iretq` with KPTI on | `#PF` right after the return, usually a double fault or a panic |
| Wrong trampoline offset | The `pop` count is off, so `iretq` runs with a shifted stack. Crashes that look random |
| ROP chain in user memory, SMAP on | `#PF` the moment ring 0 reads it |
| `ret` into a user function, SMEP on | `#PF` at execution |

The last three rows are a different character. Omitting `swapgs` and a wrong trampoline offset are slow to debug because **the symptom is far from the cause**. When it blows up well after the return rather than right at it, suspect these two first.

## 5. What is enabled right now

Check this first, because it decides the entire choice of technique.

```bash
grep -o 'smep\|smap\|pti\|pcid' /proc/cpuinfo | sort -u
dmesg | grep -i 'page table isolation\|smep\|smap'
cat /sys/devices/system/cpu/vulnerabilities/meltdown
```

In a practice environment, reading the QEMU launch script is faster. That's where the switches are.

```
-cpu qemu64,+smep,+smap
-append "... nopti nokaslr"
```

Drop `+smep,+smap` and user memory is yours to use freely; add `nopti` and the return is done in the two lines `swapgs; iretq`. A good order is to turn everything off first and get the return path correct, then enable them one at a time and watch which extra step each one demands.

## Saving user state

The four values in the return frame are best saved before going in.

```c
unsigned long user_cs, user_ss, user_rsp, user_rflags;

void save_user_state(void)
{
	__asm__ volatile(
		"movq %%cs,  %0\n"
		"movq %%ss,  %1\n"
		"movq %%rsp, %2\n"
		"pushfq\n"
		"popq %3\n"
		: "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
		:
		: "memory"
	);
}
```

Bake the selector values in as constants and, in an environment with a different kernel configuration, they show up as a `#GP` with no visible cause. The table earlier is for reading dumps; the values that actually go into the return frame always come from here.

## Summary

What the CPU demands in the post-trigger stretch comes down to four things.

**CS and SS paired, at ring 3 values.** Privilege is CS's low two bits, and `iretq` checks consistency against SS.

**The five-slot frame in the exact order.** Same layout as the top five slots of `pt_regs`.

**`swapgs` exactly once per boundary.** Both omitting it and doubling it have delayed symptoms.

**CR3 pointed at the user side.** Only needed with KPTI on; swap it yourself or borrow the kernel trampoline.

That is the part with no overlap with techniques or the allocator. Conversely, the history of mode transitions, the era when segmentation did privilege checks, SMM, the evolution of paging — none of that is needed in this stretch. It is interesting enough that I intend to write it up separately.
