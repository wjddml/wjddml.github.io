---
title: "The Cinder Engine — ARM 바이너리에 내장된 커스텀 VM 역산"
date: 2026-09-06
tags: ["rev", "custom-vm", "firmware", "crypto", "arm"]
categories: ["Cyber Apocalypse 2026"]
summary: "stripped ARM aarch64 바이너리에 내장된 커스텀 VM의 ISA를 복원하고, 펌웨어 안에 구현된 8라운드 SPN 블록 암호를 역산해 플래그를 복구한다."
translationKey: "cinder-engine"
---

## 개요

배포 파일은 `cinder` 하나다.

```
$ file cinder
cinder: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, stripped
```

실행하면 패스워드를 입력받고 참/거짓만 출력한다. aarch64에 stripped, PIE까지 걸려 있어 첫인상은 부담스럽지만, 실제 검증 로직은 네이티브 코드에 없다. 바이너리 안에 펌웨어 이미지가 박혀 있고 `cinder`는 그것을 실행하는 인터프리터다.

작업 순서는 다음과 같이 잡았다.

1. 네이티브 코드에서 VM 인터프리터 식별, ROM 위치와 크기 확보
2. 펌웨어 덤프
3. 디스패치 분기에서 ISA 복원, 디스어셈블러 작성
4. 펌웨어 내 데이터 영역 분류
5. 선형 계층 행렬 추출
6. 8라운드 역산으로 패스워드 복구
7. 패스워드로 플래그 복호화

ISA 복원까지는 비교적 수월했고, 디스어셈블 결과에서 암호 연산을 되짚는 4~6단계에 시간이 가장 많이 들었다.

## 1. 인터프리터 식별

aarch64가 처음이면 여기서 주춤하기 쉬운데, x86-64 ELF와 접근 방식은 다르지 않다. 명령어 집합만 다를 뿐 디컴파일러가 붙으면 읽는 흐름은 같다. 오히려 고정폭 4바이트에 레지스터가 넉넉해서 디컴파일 결과가 x86보다 정돈되어 나오는 편이다.

stripped라 심볼이 없으므로 구조로 찾는다. 인터프리터 본체는 형태가 뚜렷하다. 바이트 네 개를 읽어 32비트로 합치고, 그중 한 바이트로 거대한 분기를 타고, 각 분기가 같은 전역 배열을 인덱싱한다.

디컴파일 결과에서 세 개의 전역이 나온다.

| 심볼 | 용도 | 근거 |
|---|---|---|
| `DAT_00100e80` | ROM (펌웨어) | 명령어 인출 대상 |
| `DAT_00113018` | 레지스터 파일 | 4바이트 단위, 니블로 인덱싱 |
| `DAT_00113058` | RAM | 바이트 단위, `& 0xffff` |

레지스터 파일과 RAM의 주소 차이가 `0x40`이다. 4바이트 × 16개, 즉 **32비트 레지스터 16개**다. RAM은 `& 0xffff` 마스크가 붙으니 **64KB**다.

여기서 2단계에 필요한 값이 그대로 나온다. ROM 베이스가 파일 오프셋 `0xe80`이고, ROM 접근 명령에 이런 코드가 붙어 있다.

```c
// opcode 0xc6 (LDR_ROM)
reg[rd] = ROM[(imm16 + reg[rs1]) % 0x131e];
```

**모듈러 상수가 곧 펌웨어 크기다.** 크기를 추정하거나 데이터 배치로 역산할 필요 없이 `0x131e`로 확정된다.

**주의할 점.** PIE라서 정적 분석 도구가 보여주는 주소는 이미지 베이스 기준 오프셋이다. 동적 분석과 대조할 때는 실행 시 베이스를 더해야 한다. aarch64 바이너리를 x86 머신에서 실행하려면 `qemu-aarch64`가 필요하다.

```
$ qemu-aarch64 -L /usr/aarch64-linux-gnu ./cinder
```

## 2. 펌웨어 덤프

1단계에서 확보한 두 값을 그대로 쓴다.

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

## 3. ISA 복원

명령어 인출부의 비트 연산이 형식을 그대로 보여준다.

```c
word = byte3 << 24 | byte2 << 16 | byte1 << 8 | byte0;

imm16 = word & 0xffff;
rd    = byte2 >> 4;
rs1   = byte2 & 0xf;
rs2   = byte0 & 0xf;
```

4바이트 고정폭이고, 리틀엔디안 32비트 워드로 읽으면 배치가 정리된다.

```
 31    24 23  20 19  16 15               0
+--------+------+------+------------------+
| opcode |  rd  | rs1  |      imm16       |
+--------+------+------+------------------+
                              rs2 = imm16 & 0xF
```

레지스터 두 개가 한 바이트에 니블 단위로 들어가고, 3피연산자 명령은 `rs2`를 즉치값 하위 니블에서 다시 꺼내 쓴다. 즉치값을 쓰는 명령과 레지스터 세 개를 쓰는 명령이 같은 필드를 겹쳐 쓴다.

부호 확장은 이렇게 처리한다.

```c
imm16_s = (byte1 << 8) & 0x8000 ? (word | 0xffff0000) : imm16;
```

분기 목적지는 `uVar2 + imm16_s`이고 `uVar2`는 이미 `pc + 4`다. 즉 **`pc + 4 + offset`**이지 `pc + offset`이 아니다. 명령 하나를 인출하며 PC를 먼저 올리는 구조라 그렇다. 이 4바이트 차이 때문에 분기가 한 명령씩 밀려 보이는 실수가 흔하다.

### opcode 표

| opcode | 명령 | 동작 |
|---|---|---|
| `0x00` | HALT | 종료 |
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
| `0xa0` | JMP | 무조건 분기 |
| `0xa1` | JZ | `Z`면 분기 |
| `0xa2` | JNZ | `Z`가 아니면 분기 |
| `0xc4` | LDR | `rd = RAM[(rs1 + imm16) & 0xffff]` |
| `0xc5` | STR | `RAM[(rs1 + imm16) & 0xffff] = rd & 0xff` |
| `0xc6` | LDR_ROM | `rd = ROM[(rs1 + imm16) % 0x131e]` |
| `0xe0` | GETC | 입력 한 바이트, 소진 시 `Z = 1` |
| `0xe1` | PUTC | `rs1 & 0xff` 출력 |

opcode가 상위 니블 기준으로 묶여 있어 표를 채우는 속도가 붙는다. `0x29`가 회전 계열로 확인되면 `0x2a`~`0x2c`도 같은 계열이라고 보고 검증하면 된다.

메모리 접근이 RAM과 ROM으로 갈리는 점이 중요하다. 상수 테이블이 코드와 같은 이미지 안에 있다는 뜻이고, 실제로 S-box와 라운드 키가 거기서 나온다.

### 대회 당시의 오류 세 가지

아래 표는 대회 중 작성한 디스어셈블러와 재검토 후 확인한 실제 동작의 차이다. 셋 다 그때는 잡지 못했고, 그래도 풀이는 통과했다.

| 항목 | 당시 표기 | 실제 동작 |
|---|---|---|
| `0x2a`~`0x2c` 시프트량 | `r{rs2}` | 즉치값 `byte0 & 0x1f` |
| `0x29` 회전량 | `imm16_s` | `(-imm) & 0x1f` (실질 좌회전) |
| `0xa1` / `0xa2` | JNZ / JZ | JZ / JNZ |

시프트 계열은 `rs2 = byte0 & 0xf`와 시프트량 `byte0 & 0x1f`의 하위 4비트가 겹친다. 그래서 대부분의 명령에서 같은 숫자가 찍히고, bit 4가 서는 경우에만 어긋난다. 눈으로 훑어서는 잡히지 않는 종류의 오류다.

분기 극성은 완전히 반대였다. 그런데도 결과에 영향이 없었던 이유는 5단계에서 드러난다. 실제로 읽어야 했던 선형 계층 구간에 분기가 하나도 없었기 때문이다. 분기가 섞인 구간을 해석해야 했다면 흐름을 통째로 잘못 따라갔을 것이다.

풀이가 통과한 것과 ISA를 정확히 복원한 것은 별개다. 이 문제에서는 필요한 부분만 맞으면 됐다.

### 플래그 갱신 범위

단일 Z 플래그 하나뿐인데, 갱신 주체가 CMP만이 아니다. ADD·SUB·AND·OR·XOR·MUL·ADDI가 전부 결과가 0인지로 이 플래그를 건드리고, GETC도 입력이 소진되면 세운다. 조건 분기 앞에 산술 명령이 하나 끼는 것만으로 의미가 바뀌므로 직전 명령을 같이 봐야 한다.

### 디스어셈블러

```python
opcode   = byte3
reg_dest = (byte2 >> 4) & 0xF
reg_src1 =  byte2       & 0xF
reg_src2 =  byte0       & 0xF

imm16_u = (byte1 << 8) | byte0
imm16_s = imm16_u if not (imm16_u & 0x8000) else imm16_u - 0x10000

jmp_target = pc + 4 + imm16_s
```

## 4. 데이터 영역 분류

디스어셈블 결과에서 코드가 끝나는 지점을 찾으면 그 뒤는 전부 데이터다.

| 오프셋 | 크기 | 내용 |
|---|---|---|
| `0x0000` ~ | — | 코드 (`0x0070`~`0x1018`이 선형 계층) |
| `0x10c4` | 256 | S-box |
| `0x11c4` | 288 | 라운드 키 9 × 32 |
| `0x12e4` | 32 | 목표 상태 |
| `0x1304` | 26 | 암호화된 플래그 |
| `0x131e` | | 끝 |

마지막이 `0x131e`에서 정확히 끝난다. 1단계에서 확보한 크기와 맞아떨어지므로 분류가 빠짐없이 됐다고 볼 수 있다.

S-box는 256바이트에 값이 중복 없이 채워져 있어 바로 알아볼 수 있다. 라운드 키가 9개이고 상태가 32바이트라는 점에서 구조가 정해진다. **8라운드 SPN**이다. 라운드마다 키를 더하고, S-box로 치환하고, 선형 계층으로 섞는다. AES와 뼈대가 같고 파라미터만 다르다.

목표 상태가 펌웨어에 박혀 있다는 것은 입력을 암호화한 결과를 이 값과 비교한다는 뜻이다. 되돌리면 요구되는 입력이 나온다.

## 5. 선형 계층 행렬 추출

여기서 방법을 갈랐다.

S-box와 라운드 키는 테이블이라 잘라내면 끝이다. 선형 계층은 테이블이 아니라 코드로 구현되어 있다. `0x0070`부터 `0x1018`까지 약 4KB, 명령 수로 천 개 단위가 전부 그 부분이다.

명령을 하나씩 읽어 어떤 입력 바이트가 어떤 출력 바이트에 XOR되는지 손으로 추적할 수는 있다. 다만 언롤된 `LDR`/`XOR`/`STR` 반복이라 옮겨 적는 과정에서 실수가 누적되고, 틀렸는지 확인할 방법도 마땅치 않다.

대신 선형 변환의 성질을 이용한다. 각 출력 바이트가 입력 바이트 몇 개의 XOR이라면, 입력 하나만 바꿨을 때 값이 변하는 출력 자리가 그 입력이 기여하는 자리다. 32번 실행하면 32×32 행렬이 전부 나온다.

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

`base_out`을 따로 재는 이유가 있다. 이 계층은 순수 선형이 아니라 상수가 더해진 아핀 변환이다. 영벡터를 넣어 상수항을 먼저 구하고 나머지를 그것과 XOR해 선형 부분만 남긴다. 이 처리를 빼면 행렬은 그럴듯하게 나오지만 역산 결과가 어긋난다.

### 에뮬레이터는 opcode 세 개면 된다

탐침을 하려면 해당 구간을 실행해야 한다. VM 전체를 구현할 필요는 없다.

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

실제 RAM은 64KB지만 이 구간이 쓰는 주소는 입력 0~31, 출력 128~159뿐이라 256바이트로 충분하다. opcode 세 개만 처리하고 분기 없이 처음부터 끝까지 직진한다.

이게 성립하는 조건은 해당 구간이 완전히 언롤된 직선 코드라는 것이다. 고정된 32바이트 선형 변환이라 루프를 돌 이유가 없고, 디스어셈블 결과에도 그 구간에는 분기가 없다.

**확인하고 넘어갈 것.** 실행 전에 해당 구간에 `0xa0`~`0xa2`가 없는지 확인하는 편이 안전하다. 하나라도 있으면 이 단순 실행기는 잘못된 결과를 내놓고, 그것도 조용히 그렇게 된다.

전체 ISA를 복원한 작업이 헛되지는 않았다. 이 구간이 직선 코드이고 쓰이는 명령이 세 개뿐이라는 판단 자체가 디스어셈블 결과가 있어야 가능하다. 다만 실행기는 필요한 만큼만 만들면 된다.

## 6. 역산

행렬을 GF(2)에서 역으로 만든다. 원소가 0과 1뿐이라 가우스 소거의 뺄셈이 XOR이 된다.

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

피벗을 못 찾으면 즉시 종료하도록 두었다. 행렬이 특이행렬로 나온다는 것은 5단계의 탐침이 잘못됐다는 신호다. 정상적인 암호의 선형 계층은 항상 가역이므로 여기서 멈추는 편이 낫다.

이제 목표 상태에서 8라운드를 거꾸로 감는다. 정방향이 `키 XOR → S-box → 선형 계층` 순이므로 역방향은 순서를 뒤집는다.

```python
state = target[:]
for r in range(8, 0, -1):
    state = [state[i] ^ round_keys[r][i] for i in range(32)]
    state = [state[i] ^ base_out[i]      for i in range(32)]   # 아핀 상수 제거

    new_state = [0] * 32
    for i in range(32):
        for j in range(32):
            if inv_mix_matrix[i][j]:
                new_state[i] ^= state[j]

    state = [inv_sbox[b] for b in new_state]

required_input = [state[i] ^ round_keys[0][i] for i in range(32)]
```

라운드 키 인덱스에 주의한다. 키가 9개인데 라운드는 8회다. 마지막 라운드 뒤에 키를 한 번 더 더하는 구조이므로 역방향은 `round_keys[8]`에서 시작해 `round_keys[0]`으로 끝난다. 인덱스가 하나 밀리면 결과가 전부 어긋나는데 중간 검증 수단이 없어 원인을 찾기 번거롭다.

## 7. 플래그 복호화

복구한 32바이트를 넣으면 검증은 통과한다. 다만 그것이 플래그는 아니다.

`0x1304`에 26바이트가 별도로 있고, 이것이 패스워드로 XOR된 플래그다.

```python
enc_flag = list(rom[0x1304 : 0x1304 + 26])
flag = "".join(chr(required_input[i] ^ enc_flag[i]) for i in range(26))
```

검증 통과와 플래그 획득을 분리해둔 구성이다. 4단계에서 데이터 영역을 끝까지 분류해두지 않았다면 여기서 한 번 더 되돌아가야 했다.

## 정리

- ARM aarch64는 x86-64와 도구 및 접근 방식이 크게 다르지 않다. stripped PIE라는 조건이 더 큰 변수였다.
- 인터프리터 본체에 ROM 베이스와 크기, 레지스터 개수, RAM 크기가 전부 상수로 박혀 있다. 펌웨어를 뜯기 전에 이것부터 확보하면 이후 단계에서 추정할 일이 줄어든다.
- 커스텀 VM 문제는 ISA 복원이 끝이 아니다. 이번 경우 시간의 대부분은 복원된 어셈블리에서 암호 구조를 읽어내는 데 들어갔다.
- 언롤된 선형 코드는 읽는 것보다 실행해서 관측하는 편이 정확하고 빠르다. 32회 실행으로 행렬 전체를 얻었다.
- 부분 에뮬레이터로 충분한 경우가 많다. 다만 그 전제인 직선 코드 여부는 확인하고 넘어가야 한다.

---

전체 스크립트: [ctf-writeups/2026-cyber-apocalypse/the-cinder-engine](https://github.com/wjddml/ctf-writeups/tree/main/2026-cyber-apocalypse/the-cinder-engine)
