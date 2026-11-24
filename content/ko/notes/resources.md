---
title: "참고한 사이트와 블로그"
date: 2026-11-24
tags: ["resources", "pwn", "kernel", "web3", "ctf"]
categories: ["resources"]
summary: "학습과 실습에 참고한 플랫폼, 문제 사이트, 블로그를 분야별로 정리했다."
translationKey: "resources"
---

북마크가 백 개를 넘어가서 분야별로 정리했다.

## 학습 플랫폼

[pwn.college](https://pwn.college/) — 애리조나 주립대(ASU)에서 만든 시스템 보안 교육 플랫폼이다. 실제 대학 강의에 쓰이는 교재를 공개한 것이고 누구나 무료로 들을 수 있다. 리눅스와 어셈블리 기초부터 프로그램 보안, 커널, 리버싱, 마이크로아키텍처까지 모듈로 나뉘어 있고 모듈마다 실습 문제가 붙는다. 이름이 pwn이지만 다루는 범위는 바이너리 익스플로잇보다 넓다.

[OST2](https://p.ost2.fyi/) — OpenSecurityTraining2에서 운영하는 무료 강의 사이트다. x86-64와 ARM64 아키텍처, OS 내부 구조, 가상화, UEFI 펌웨어, 리버싱 같은 저수준 주제가 중심이다. 강의마다 슬라이드와 영상, 실습 코드가 함께 제공된다.

## pwn 문제 사이트

[pwnable.tw](https://pwnable.tw/) — 상시 운영되는 pwn 워게임이다. 난도가 높은 편이다.

[pwnable.xyz](https://pwnable.xyz/) — 상시 운영되는 워게임이다. 문제 하나의 단위가 비교적 짧다.

[pwnable.kr](https://pwnable.kr/) — 오래 운영된 워게임이다. 입문부터 고난도까지 난이도 폭이 넓다.

[AlpacaHack](https://alpacahack.com/) — 일본 기반의 CTF 플랫폼이다. 개인전 단기 라운드를 정기적으로 열고 라운드가 끝나면 문제를 상시 공개한다. pwn과 리버싱 외에 웹, 암호학 등 분야가 넓고, 매일 한 문제씩 공개하는 Daily AlpacaHack도 운영한다.

[Dreamhack](https://dreamhack.io/) — Theori가 운영하는 한국어 플랫폼이다. 개념 강의와 문제가 같이 있어서 분야 입문에 쓸 수 있다. pwn 외에 웹, 리버싱, 암호학도 다룬다.

[exploit.education](https://exploit.education/) — Nebula, Protostar, Phoenix 등의 문제 세트를 제공한다. 메모리 커럽션 기초를 순서대로 다룬다.

[ROP Emporium](https://ropemporium.com/) — ROP만 다루는 문제 세트다. 같은 문제를 x86, x86-64, ARM, MIPS로 제공해서 아키텍처별 차이를 볼 수 있다.

## 힙

glibc 힙 자료다.

[how2heap](https://github.com/shellphish/how2heap) — CTF 팀 Shellphish가 관리하는 저장소다. glibc 버전별로 어떤 기법이 동작하는지 PoC로 정리되어 있어서, 버전이 올라가면서 막힌 기법을 확인할 때 쓴다.

[MallocInternals](https://sourceware.org/glibc/wiki/MallocInternals) — glibc 공식 위키 문서다. bin 구조와 tcache 동작의 1차 자료다.

[sploitfun](https://sploitfun.wordpress.com/) — 오래된 글이지만 unsorted bin 설명이 정확하다.

[dhavalkapil](https://heap-exploitation.dhavalkapil.com/) — 힙 익스플로잇을 책 형태로 정리한 문서다.

## 커널

[pawnyable](https://pawnyable.cafe/) — Linux 커널 익스플로잇 입문 자료다. QEMU 환경 구성부터 기법별 설명과 실습 커널 모듈까지 이어진다.

[Learning Linux Kernel Exploitation](https://lkmidas.github.io/) — 커널 익스플로잇 입문 연작이다. pawnyable과 다루는 범위가 겹치는데 설명 방식이 달라서 같이 보면 도움이 된다.

[arttnba3](https://arttnba3.cn/) — 커널 익스 기법을 단계별로 정리한 글이 많다.

## 마이크로아키텍처

[CPU 내부 다이어그램](https://mdsattacks.com/diagram.html) — 파이프라인과 각종 버퍼 구조를 눌러보면서 볼 수 있다. 어느 단계의 어느 버퍼가 공격 대상인지 확인할 때 쓴다.

[transient.fail](https://transient.fail/) — transient execution 공격의 분류와 계보를 정리한 사이트다. 이름이 비슷한 변종이 많아서 대조할 때 필요하다.

## Web3

[Ethernaut](https://ethernaut.openzeppelin.com/) — OpenZeppelin이 만든 스마트 컨트랙트 취약점 문제 모음이다. 레벨마다 컨트랙트 하나씩 주고 특정 취약점 유형을 다룬다. 브라우저 콘솔로 풀 수도 있고 Foundry로 로컬 테스트 후 테스트넷에 제출하는 방식도 된다.

[Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/) — 프로토콜 단위 취약점을 다룬다. 플래시 론, 오라클 조작, 거버넌스 쪽 문제가 들어 있다.

[Cyfrin Updraft](https://updraft.cyfrin.io/courses) — 감사 회사 Cyfrin이 운영하는 무료 강의다. 스마트 컨트랙트 개발과 보안 감사를 다룬다.

[minaminao/ctf-blockchain](https://github.com/minaminao/ctf-blockchain) — 블록체인 CTF 문제와 풀이를 취약점 유형별로 모아둔 저장소다. 어떤 유형이 실제로 출제되는지 볼 수 있다.

[evm-ctf-challenges](https://github.com/MiloTruck/evm-ctf-challenges) — EVM 문제 모음이다.

[DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) — 실제 해킹 사례를 Foundry 테스트로 재현해둔 저장소다. 교육용으로 만든 문제가 아니라 실제 사고 기록이다.

[EVM Puzzles](https://github.com/fvictorio/evm-puzzles) — 바이트코드를 읽고 통과하는 calldata를 찾는 문제다.

[onlypwner](https://onlypwner.xyz/) — 스마트 컨트랙트 문제 플랫폼이었다. 2026년 10월 말 운영 종료 공지가 올라왔다.

그 외 문제 플랫폼과 강의: [Capture the Ether](https://capturetheether.com/) · [Ciphershastra](https://ciphershastra.com/index.html) · [CTF Protocol](https://www.ctfprotocol.com/) · [MEVSec](https://ctf.mevsec.com/) · [Node Guardians](https://nodeguardians.io/) · [Curta](https://www.curta.wtf/) · [SpeedRun Ethereum](https://speedrunethereum.com/) · [EthTechTree](https://www.ethtechtree.com/) · [BuidlGuidl CTF](https://ctf.buidlguidl.com/) · [mrstealyocrypto](https://mrstealyocrypto.xyz/) · [WTF Academy](https://www.wtf.academy/en) · [CryptoZombies](https://cryptozombies.io/en/course) · [School of Solana](https://ackee.xyz/school-of-solana) · [VyperPunk](https://github.com/defcongroup0532/VyperPunk) · [zkHack](https://zkhack.dev/) · [RareSkills](https://github.com/RareSkills) · [QuillAudits](https://www.quillaudits.com/) · [Kaia 부트캠프](https://www.kaia.io/ko/bootcamp-module-1)

## Web3 블로그

[TrustSec](https://trustsec.xyz/blog) · [MiloTruck](https://milotruck.github.io/) · [Program the Blockchain](https://programtheblockchain.com/) · [Remedy](https://r.xyz/blog)

## 블로그 — 익스플로잇 중심

[kylebot](https://blog.kylebot.net/) — 글 수는 적지만 한 편이 길고 깊다. glibc FILE 구조체를 이용한 익스플로잇(FSROP), 커널 CVE 분석, 난도 높은 CTF pwn 문제 풀이를 다룬다.

[ptr-yudai](https://ptr-yudai.hatenablog.com/) — pawnyable을 만든 사람의 블로그다. 커널과 브라우저 쪽 CTF 문제 풀이가 많다.

[CuB3y0nd](https://www.cubeyond.net/) — 바이너리 익스플로잇, Windows, IoT, 자동화를 다룬다. CTF 풀이 외에 ptmalloc2 소스 분석, Intel CET 우회, ARM64 ROP, 오픈소스 라이브러리 퍼징으로 찾은 CVE 분석 같은 글이 있다. 글 길이가 길고 연작이 많다.

## 블로그 — 그 외

보안이라는 공통점 외에는 범위가 제각각이다. 한 사람이 프로토콜 분석, 침투테스트, 바이너리 분석, CTF 기록을 같이 올리는 경우가 많아서 분야로 나누지 않았다.

[zolutal](https://blog.zolutal.io/) · [n132](https://n132.github.io/) · [k4lizen](https://hazyclimb.dev/) · [elma](https://blog.elmo.sg/) · [nasm](https://nasm.re/) · [x3h1n](https://x3h1n.github.io/) · [Philip Dobranowski](https://philipdobranowski.com/blog) · [dasian](https://dasian.github.io/) · [kqx](https://kqx.io/) · [mhackeroni](https://mhackeroni.it/) · [Nightmare](https://guyinatuxedo.github.io/index.html) · [Advent of Pwn 2025](https://www.feyrer.de/CTF/CTF-Writeup-pwn.college-AdventOfPwn2025/) · [f0rget](https://f0rget.me/) · [x2nn](https://x2nn.github.io/) · [0p1n](https://lkliki.github.io/links/) · [Rayanfam](https://rayanfam.com/) · [idafchev](https://idafchev.github.io/blog/) · [0x434b](https://0x434b.dev/) · [Dhaval Kapil](https://dhavalkapil.com/archive/) · [omarafal](https://omarafal.github.io/) · [r1ru](https://r1ru.github.io/) · [Deep Kondah](https://www.deep-kondah.com/) · [gtrboy](https://gtrboy.github.io/) · [LiveOverflow](https://liveoverflow.com/) · [Saar Amar](https://saaramar.github.io/Publications/)

## 연구자 홈페이지

블로그가 아니라 논문 발표 목록이다.

[Zhenpeng Lin](https://zplin.me/) · [Yoochan Lee](https://leeyoochan.github.io/publications/) · [Lukas Maar](https://lukasmaar.github.io/) · [Tong Liu](https://lyutoon.github.io/) · [Daniel Genkin](https://genkin.io/) · [Zion Basque](https://www.zionbasque.com/papers) · [Marcos Bajo](https://h3xduck.github.io/) · [Shaopeng Lin](https://shaopenglin.github.io/publications/)

## 관심 있는 다른 분야

앞으로 해볼 생각이 있는 분야들이다.

**macOS·iOS** [Mickey Jin](https://jhftss.github.io/) · [Zechao Cai](https://zechao.org/) · [Siguza](https://siguza.net/)

**Windows** [cebola](https://mdanilor.github.io/posts/) · [FuzzySecurity](https://fuzzysecurity.com/index.html) · [wetw0rk](https://wetw0rk.github.io/) · [Osanda](https://osandamalith.com/)

**침투테스트** [Hack The Box](https://www.hackthebox.com/) · [TryHackMe](https://tryhackme.com/) · [HackMyVM](https://hackmyvm.eu/) · [PentesterLab](https://pentesterlab.com/) · [revshells](https://www.revshells.com/)

**웹** [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Burp Suite를 만든 PortSwigger가 운영하는 무료 실습 사이트다. · [Lord of SQLi](https://los.rubiya.kr/)

**암호학** [CryptoHack](https://cryptohack.org/)

**OSINT** [OSINT Dojo](https://www.osintdojo.com/) · [OSINT CTF](https://github.com/securekomodo/OSINT-CTF) · [Sofia Santos 연습 목록](https://gralhix.com/list-of-osint-exercises/)

**클라우드** [flAWS](http://flaws.cloud/) · [flAWS 2](http://flaws2.cloud/) — AWS 설정 오류를 단계별로 다루는 연습이다. · [Kubernetes Goat](https://madhuakula.com/kubernetes-goat/) · [cloud-security-resources](https://github.com/Lukman-01/cloud-security-resources)

**모바일** [Hextree](https://www.hextree.io/) — 안드로이드 보안 중심 강의 사이트다. · [Mobisec](https://mobisec.reyammer.io/)

**AI** [GPA](https://gpa.43z.one/) · [Agent Breaker](https://play.lakera.ai/agent-breaker) · [Prompt Airlines](https://promptairlines.com/) · [PortSwigger LLM attacks](https://portswigger.net/web-security/llm-attacks) · [Dreadnode](https://dreadnode.io/) · [Damn Vulnerable LLM Agent](https://github.com/ReversecLabs/damn-vulnerable-llm-agent) · [huntr](https://huntr.com/)

**기타** [SadServers](https://sadservers.com/) · [Protohackers](https://protohackers.com/)
