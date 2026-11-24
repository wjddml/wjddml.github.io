---
title: "Sites and Blogs I Use"
date: 2026-11-24
tags: ["resources", "pwn", "kernel", "web3", "ctf"]
categories: ["resources"]
summary: "The platforms, challenge sites and blogs I've used for study and practice, grouped by topic."
translationKey: "resources"
---

My bookmarks passed a hundred, so I sorted them by topic.

## Learning platforms

[pwn.college](https://pwn.college/) — A systems security education platform built at Arizona State University (ASU). It is the material from their actual university course, published for anyone to take for free. It runs from Linux and assembly basics through program security, kernel, reverse engineering and microarchitecture, split into modules, each with its own practice challenges. Despite the name, it covers more than binary exploitation.

[OST2](https://p.ost2.fyi/) — A free course site run by OpenSecurityTraining2. It centers on low-level subjects: x86-64 and ARM64 architecture, OS internals, virtualization, UEFI firmware and reverse engineering. Each course comes with slides, video and lab code.

## pwn challenge sites

[pwnable.tw](https://pwnable.tw/) — A permanent pwn wargame. On the harder side.

[pwnable.xyz](https://pwnable.xyz/) — A permanent wargame. Individual challenges are relatively small in scope.

[pwnable.kr](https://pwnable.kr/) — A long-running wargame. The difficulty range is wide, from beginner to advanced.

[AlpacaHack](https://alpacahack.com/) — A Japan-based CTF platform. It runs short individual-player rounds regularly and publishes the challenges permanently once a round ends. Coverage is broad — web and crypto alongside pwn and reversing — and it also runs Daily AlpacaHack, releasing one challenge a day.

[Dreamhack](https://dreamhack.io/) — A Korean-language platform run by Theori. Lessons and challenges sit side by side, which makes it usable for getting into a new category. Covers web, reversing and crypto as well as pwn.

[exploit.education](https://exploit.education/) — Provides challenge sets such as Nebula, Protostar and Phoenix. Works through memory corruption basics in order.

[ROP Emporium](https://ropemporium.com/) — A challenge set about nothing but ROP. The same challenges are offered for x86, x86-64, ARM and MIPS, so you can see the differences between architectures.

## Heap

glibc heap material.

[how2heap](https://github.com/shellphish/how2heap) — A repository maintained by the CTF team Shellphish. It documents which techniques work on which glibc version as runnable PoCs, which is what I use to check what a version bump closed off.

[MallocInternals](https://sourceware.org/glibc/wiki/MallocInternals) — The official glibc wiki page. The primary source on bin structure and tcache behavior.

[sploitfun](https://sploitfun.wordpress.com/) — Old posts, but the unsorted bin explanation is accurate.

[dhavalkapil](https://heap-exploitation.dhavalkapil.com/) — Heap exploitation written up in book form.

## Kernel

[pawnyable](https://pawnyable.cafe/) — Introductory Linux kernel exploitation material. It runs from setting up a QEMU environment through technique-by-technique explanation, with practice kernel modules.

[Learning Linux Kernel Exploitation](https://lkmidas.github.io/) — An introductory kernel exploitation series. It overlaps with pawnyable in scope but explains things differently, so reading both helps.

[arttnba3](https://arttnba3.cn/) — Many posts working through kernel exploitation techniques step by step.

## Microarchitecture

[CPU internals diagram](https://mdsattacks.com/diagram.html) — An interactive view of the pipeline and the various buffers. I use it to check which buffer at which stage a given attack targets.

[transient.fail](https://transient.fail/) — A site cataloguing transient execution attacks and how they relate to each other. There are a lot of similarly named variants, so a reference to cross-check against is necessary.

## Web3

[Ethernaut](https://ethernaut.openzeppelin.com/) — A set of smart contract vulnerability challenges from OpenZeppelin. Each level hands you one contract and covers a specific class of bug. You can solve them from the browser console, or test locally with Foundry and submit to a testnet.

[Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/) — Protocol-level vulnerabilities. Flash loans, oracle manipulation and governance are all in there.

[Cyfrin Updraft](https://updraft.cyfrin.io/courses) — Free courses from the audit firm Cyfrin, covering smart contract development and security auditing.

[minaminao/ctf-blockchain](https://github.com/minaminao/ctf-blockchain) — A repository collecting blockchain CTF challenges and solutions by vulnerability class. Useful for seeing which classes actually show up in competition.

[evm-ctf-challenges](https://github.com/MiloTruck/evm-ctf-challenges) — A set of EVM challenges.

[DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) — A repository reproducing real hacks as Foundry tests. Not purpose-built exercises but records of actual incidents.

[EVM Puzzles](https://github.com/fvictorio/evm-puzzles) — Read the bytecode and find calldata that gets through it.

[onlypwner](https://onlypwner.xyz/) — A smart contract challenge platform. A shutdown notice went up in late October 2026.

Other platforms and courses: [Capture the Ether](https://capturetheether.com/) · [Ciphershastra](https://ciphershastra.com/index.html) · [CTF Protocol](https://www.ctfprotocol.com/) · [MEVSec](https://ctf.mevsec.com/) · [Node Guardians](https://nodeguardians.io/) · [Curta](https://www.curta.wtf/) · [SpeedRun Ethereum](https://speedrunethereum.com/) · [EthTechTree](https://www.ethtechtree.com/) · [BuidlGuidl CTF](https://ctf.buidlguidl.com/) · [mrstealyocrypto](https://mrstealyocrypto.xyz/) · [WTF Academy](https://www.wtf.academy/en) · [CryptoZombies](https://cryptozombies.io/en/course) · [School of Solana](https://ackee.xyz/school-of-solana) · [VyperPunk](https://github.com/defcongroup0532/VyperPunk) · [zkHack](https://zkhack.dev/) · [RareSkills](https://github.com/RareSkills) · [QuillAudits](https://www.quillaudits.com/) · [Kaia bootcamp](https://www.kaia.io/ko/bootcamp-module-1)

## Web3 blogs

[TrustSec](https://trustsec.xyz/blog) · [MiloTruck](https://milotruck.github.io/) · [Program the Blockchain](https://programtheblockchain.com/) · [Remedy](https://r.xyz/blog)

## Blogs — exploitation

[kylebot](https://blog.kylebot.net/) — Not many posts, but each one is long and goes deep. Exploitation via glibc FILE structures (FSROP), kernel CVE analysis, and hard CTF pwn challenges.

[ptr-yudai](https://ptr-yudai.hatenablog.com/) — The blog of the person behind pawnyable. Mostly kernel and browser CTF challenges.

[CuB3y0nd](https://www.cubeyond.net/) — Binary exploitation, Windows, IoT and automation. Beyond CTF writeups there are posts on ptmalloc2 source analysis, Intel CET bypass, ARM64 ROP, and CVEs found by fuzzing open-source libraries. Posts run long and often come in series.

## Blogs — everything else

Security is the only thing these have in common; the range within that is all over the place. One person will post protocol analysis, pentesting, binary analysis and CTF notes side by side, so I did not try to split them by category.

[zolutal](https://blog.zolutal.io/) · [n132](https://n132.github.io/) · [k4lizen](https://hazyclimb.dev/) · [elma](https://blog.elmo.sg/) · [nasm](https://nasm.re/) · [x3h1n](https://x3h1n.github.io/) · [Philip Dobranowski](https://philipdobranowski.com/blog) · [dasian](https://dasian.github.io/) · [kqx](https://kqx.io/) · [mhackeroni](https://mhackeroni.it/) · [Nightmare](https://guyinatuxedo.github.io/index.html) · [Advent of Pwn 2025](https://www.feyrer.de/CTF/CTF-Writeup-pwn.college-AdventOfPwn2025/) · [f0rget](https://f0rget.me/) · [x2nn](https://x2nn.github.io/) · [0p1n](https://lkliki.github.io/links/) · [Rayanfam](https://rayanfam.com/) · [idafchev](https://idafchev.github.io/blog/) · [0x434b](https://0x434b.dev/) · [Dhaval Kapil](https://dhavalkapil.com/archive/) · [omarafal](https://omarafal.github.io/) · [r1ru](https://r1ru.github.io/) · [Deep Kondah](https://www.deep-kondah.com/) · [gtrboy](https://gtrboy.github.io/) · [LiveOverflow](https://liveoverflow.com/) · [Saar Amar](https://saaramar.github.io/Publications/)

## Researcher pages

Publication lists rather than blogs.

[Zhenpeng Lin](https://zplin.me/) · [Yoochan Lee](https://leeyoochan.github.io/publications/) · [Lukas Maar](https://lukasmaar.github.io/) · [Tong Liu](https://lyutoon.github.io/) · [Daniel Genkin](https://genkin.io/) · [Zion Basque](https://www.zionbasque.com/papers) · [Marcos Bajo](https://h3xduck.github.io/) · [Shaopeng Lin](https://shaopenglin.github.io/publications/)

## Other areas I'm interested in

Areas I intend to get into.

**macOS / iOS** [Mickey Jin](https://jhftss.github.io/) · [Zechao Cai](https://zechao.org/) · [Siguza](https://siguza.net/)

**Windows** [cebola](https://mdanilor.github.io/posts/) · [FuzzySecurity](https://fuzzysecurity.com/index.html) · [wetw0rk](https://wetw0rk.github.io/) · [Osanda](https://osandamalith.com/)

**Pentesting** [Hack The Box](https://www.hackthebox.com/) · [TryHackMe](https://tryhackme.com/) · [HackMyVM](https://hackmyvm.eu/) · [PentesterLab](https://pentesterlab.com/) · [revshells](https://www.revshells.com/)

**Web** [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Free labs run by PortSwigger, who make Burp Suite. · [Lord of SQLi](https://los.rubiya.kr/)

**Crypto** [CryptoHack](https://cryptohack.org/)

**OSINT** [OSINT Dojo](https://www.osintdojo.com/) · [OSINT CTF](https://github.com/securekomodo/OSINT-CTF) · [Sofia Santos's exercise list](https://gralhix.com/list-of-osint-exercises/)

**Cloud** [flAWS](http://flaws.cloud/) · [flAWS 2](http://flaws2.cloud/) — Walks through AWS misconfigurations step by step. · [Kubernetes Goat](https://madhuakula.com/kubernetes-goat/) · [cloud-security-resources](https://github.com/Lukman-01/cloud-security-resources)

**Mobile** [Hextree](https://www.hextree.io/) — Course site focused on Android security. · [Mobisec](https://mobisec.reyammer.io/)

**AI** [GPA](https://gpa.43z.one/) · [Agent Breaker](https://play.lakera.ai/agent-breaker) · [Prompt Airlines](https://promptairlines.com/) · [PortSwigger LLM attacks](https://portswigger.net/web-security/llm-attacks) · [Dreadnode](https://dreadnode.io/) · [Damn Vulnerable LLM Agent](https://github.com/ReversecLabs/damn-vulnerable-llm-agent) · [huntr](https://huntr.com/)

**Other** [SadServers](https://sadservers.com/) · [Protohackers](https://protohackers.com/)
