---
title: "What/Who — 컨테이너에 봉인된 VM 바이트코드 역산"
date: 2026-09-18
tags: ["rev", "custom-vm", "crypto"]
categories: ["L3ak CTF 2026"]
summary: "커스텀 컨테이너 포맷을 풀어 VM 바이트코드를 꺼내고, ISA를 복원해 6개 문제의 정답을 역산한다."
translationKey: "what-who"
---

## 개요

배포 파일은 둘이다.

```
whatwho     ELF 64-bit, x86-64, stripped
vault.wwc   data
```

실행하면 인스턴스 시드를 출력하고 질문 6개를 던진다. 전부 맞히면 플래그가 나온다.

작업 순서.

1. ELF가 VM 인터프리터임을 확인
2. `vault.wwc` 컨테이너 복호화
3. ISA 복원, 디스어셈블러 작성
4. 문제 6개 역산
5. 로컬 인스턴스 복제 후 검증

## 1. ELF는 인터프리터다

gdb로 단계 실행하면 어느 문제를 풀든 같은 함수에 계속 들어간다. `sub_1CF0` 도입부를 보면 이유가 나온다.

```c
v13 = (char *)(v12 + 12 * v10);
v14 = *v13;
v15 = v13[1]; v16 = v13[2]; v17 = v13[3];
v18 = *(_QWORD *)(v13 + 4);
```

12바이트 고정폭 명령, opcode 기반 거대 switch, 레지스터 8개(`v156[1..8]`), sp(`v157`), pc(`v167`). 검증 로직은 `vault.wwc` 안의 바이트코드이고 ELF는 그것을 실행하는 CPU다.

동적 분석으로 이 구조를 따라가는 것은 의미가 없다. 컨테이너를 먼저 풀어야 한다.

## 2. vault.wwc 복호화

`sub_18C0`이 로더다. 헤더 64바이트.

```
magic 0x1A0A0D4F48575789 | ver=3 | hdrsz=64 | n_insns | data_size | entry | key | code_seal | data_seal
```

이어서 `12*n` 바이트의 코드, `data_size` 바이트의 데이터. 두 세그먼트 모두 `sub_1780`으로 스크램블되어 있다. `(key, domain, index)` 기반 splitmix 계열 키스트림에 바이트별 회전과 뺄셈이 더해진 형태다. 도메인 상수 둘은 ASCII다.

`sub_1810`이 세그먼트별 체크섬을 계산한다. **이것이 검증 수단이다.** 복호화가 한 바이트라도 틀리면 seal이 불일치하므로, 추측 없이 정확성을 확인할 수 있다.

```
insn=262 data=762 entry=0 key=91e10da5c79e7b1d
code seal True  data seal True
```

데이터 세그먼트의 문자열이 곧 문제 프롬프트다.

```
data+0x0000  Question 1 - Did you remember the password?
data+0x002d  Question 2 - What is today's special?
data+0x0054  Question 3 - Which way now?
```

## 3. ISA 복원

여기서 시간을 가장 많이 썼다. 원인은 Hex-Rays가 점프 테이블을 압축하려고 switch를 오프셋 산술로 재작성한 것이다.

```c
v23 = (unsigned __int8)(v14 + 115);
switch ((char)v23) { case 84: ... }

v19 = v14 - 37;
switch (v19) { case 0x1E: ... }
```

화면의 `case` 값은 opcode가 아니다. 첫 그룹은 `case - 115 mod 256`, 둘째 그룹은 `case + 0x25`로 되돌려야 한다. 위 두 경우 실제 opcode는 각각 `0xE1`, `0x43`이다.

모드가 둘이고 opcode 공간이 분리되어 있다는 점도 주의해야 한다. `0x0C`로 스택 모드 진입, `0xFA`로 레지스터 모드 복귀이며 sp가 0일 때만 허용된다.

필요한 명령.

| opcode | 의미 |
|---|---|
| `0x5F` | `INPUT r[A]`, fmt=B, max=C, prompt=data[imm] |
| `0x7B` | `SUBMIT imm` |
| `0xCA` | `r[A] = SEED` |
| `0x31` | `r[A] = KEY` |
| `0x43` | `flag = (r[A] == imm)` |
| `0xDD` | `flag = (r[A] == r[B])` |
| `0x2E` / `0xBC` | `JF` / `JT` |
| `0xE1` | `FLAG` |

INPUT의 fmt는 `0`=raw, `1`=hex8, `2`=hex16, `3`=hex32, `4`=dec다.

디스어셈블러는 고정폭이라 짧다.

```python
for pc in range(len(code)//12):
    op, A, B, C = code[12*pc:12*pc+4]
    imm = struct.unpack_from("<Q", code, 12*pc+4)[0]
```

명령 262개. 데이터 세그먼트는 VM 주소 `0x2000`에 로드되고 입력 버퍼는 `0x800`이다. `SUBMIT` 여섯 개를 찾으면 그 사이가 각각 한 문제다.

## 4. 문제별 역산

**Q1** 4바이트를 빅엔디안으로 묶어 `XOR → ROL32 → MUL → xorshift → ADD → ROR32` 후 `0xFB5647DA`와 비교한다. 전부 32비트 전단사라 역산이 유일하다. 곱셈은 모듈러 역원, xorshift는 반복 대입으로 되돌린다.

```python
x = rol32(0xFB5647DA, 3)
x = (x - 0x7F4A7C15) & m32
y = x
for _ in range(4):
    y = x ^ (y >> 15)
x = (y * pow(0x045D9F3B, -1, 1 << 32)) & m32
answer = (ror32(x, 9) ^ 0xC13FA9A9).to_bytes(4, "big")
```

**Q2** 스택 모드 블록. 바이트마다 `ROL8((c ^ acc) + A[i], B[i]) ^ C[i] == D[i]`이고 16바이트 테이블 넷이 `0xe9/0xf9/0x109/0x119`에 있다. `acc`는 `0x5A`에서 시작해 앞에서 뒤로 연쇄하므로 순서대로 벗긴다.

**Q3** 102글자. 이동 델타가 `N=-17, E=+1, S=+17, W=-1`이고 매 이동 후 `data[r2+0x2129]`가 1인지 확인한다. 17×17 미로, 시작 18, 종료 96.

여기에 함정이 있다. 검사 조건은 **정확히 102걸음**과 **모든 칸이 통행 가능**뿐이고 방문 기록이 없다. 최단 경로 문제가 아니라 (칸, 남은 걸음) DP로 풀어야 하며, 걸음 수가 남으면 왕복으로 채운다.

**Q4 / Q5** 둘 다 `MOV r0, SEED`로 시작한다. Q4는 splitmix 137라운드에 10진수 출력, Q5는 `((seed>>9)&0x3ff)+0x500` 라운드의 xorshift에 16자리 hex 출력이다. 루프를 그대로 옮기면 된다.

**Q6** 10라운드 Feistel. 라운드 키는 `0x250/0x2a0/0x2f0`에 있고 목표값 `(r2, r3)`은 시드와 키에서 파생된다. 역방향으로 전개한다.

```python
a, b = r2, r3
for i in range(9, -1, -1):
    a, b = b ^ F(a, i), a
```

## 5. rolling key

Q6가 시드만으로 풀리지 않는 이유다.

`v173`은 `mix(seed ^ 0x57484F5F57415443)`으로 시작한다. 상수는 리틀엔디안으로 `"WHO_WHAT"`이다. 그리고 **`SUBMIT`마다 직전에 입력한 원본 문자열로 갱신**된다.

따라서 Q6의 목표값은 Q1~Q5 답변의 정확한 바이트에 의존한다. 대소문자까지 포함이다. 순서대로 풀어야 하고 건너뛸 수 없다.

## 6. 인스턴스 복제

`main`이 `/dev/urandom`보다 환경변수를 먼저 본다.

```c
v3 = getenv("WHATWHO_NONCE");
if (strlen(v3) == 16) { ... }
```

원격이 출력한 `Instance seed:` 값을 그대로 넣으면 동일한 인스턴스가 로컬에 뜬다.

```bash
WHATWHO_NONCE=8ad2b00c27513180 ./whatwho vault.wwc
```

6개를 전부 오프라인에서 검증한 뒤 원격에 한 번만 접속하면 된다.

## 걸린 것들

- **시드가 접속마다 바뀐다.** Q1~Q3은 고정이고 Q4~Q6은 시드 의존이다. 이전 실행의 답을 그대로 붙여넣어 Q4에서 실패한 적이 있다.
- **Q5는 소문자 hex여야 한다.** 파서가 `a-f`만 받고, 받는다 해도 대소문자가 달라지면 키 해시가 달라져 Q6가 조용히 깨진다.
- **Q4는 앞자리 0을 거부한다.**

## 정리

디스패치 루프, 고정폭 명령, 별도 데이터 파일. 이 셋이 보이면 대상 바이너리는 프로그램이 아니라 CPU다. 단계 실행을 멈추고 데이터를 푸는 쪽이 빠르다.

그리고 이 문제의 모든 연산은 가역이다. 정적으로 식을 확보하면 브루트포스 없이 답이 계산된다.

---

전체 스크립트: [ctf-writeups/2026-l3ak/what-who](https://github.com/wjddml/ctf-writeups/tree/main/2026-l3ak/what-who)
