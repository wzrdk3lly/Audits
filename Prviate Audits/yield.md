# Overview

This DeFi yield protocol acted as a crypto investing management liasons for other protocols like compund, aave, and dydx. The team intended to create a simple to use protocol that could allow new crypto users to be involved with multiple protocols via one platform.

\*Due to MSA requirements I will not include detailed findings. I will only include Descriptions of how the attack occured.

# Findings

---

## [H-1] Vulnerable deposit funcitonality leads to falsly increased balance for users

## Description

In this attack scenario, I combined two low severity issues to find a high severity issue. The first issue incorporated the ability to deposit tokens without checking if the token contract returned a success. The second issue involved balance increase invariants that always equated to true, ie, even if the token contract didn't doposit token, the contract would record the deposited tokens even though it's token balance never increased. With this finding a user could inflate their balance and withdraw tokens that they never deposited.

---

## [M-1] Unchecked transfer/TransferFrom and approve calls

## Description

The contract had 15+ instances where both the transferFrom, transfer, and approve calls had no checks on their return values.

---

## [M-2] Lack of 0 address checks for admin/dao related functions

## Decriptions

The onlyOwner modifer based contracts in this review contained no 0 address checks when changing the owner and dao addresses. Any incorrect change to a 0 address would lead to a complete lock out of key protocol functions. This contract was not upgradable so they would have to redeploy a completely new version.

---

## [M-3] Incorrect infterface definition paramaters used

The protocl used an interface with incorrect parameters. Missing and out of order interface implementations will lead to a failed/reverted transaction

---

## [M-4] Loss of precision

## Description

There were 3 instances where the team used division before multiplication. While these leads to small rounding errors, the impact will be compounded over timme.

---

## [L-1] Missing access control

Users could potentially modify other's user profile data due to a missing owner assertion check. While this wouldn't lead to any immediate loss of funds, it would lead to incorrectly recorded user profiles over each user
