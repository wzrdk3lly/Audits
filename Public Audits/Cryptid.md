# Overview

Cryptid is a layer built on top of Identity's soldid implementation. Cryptid allows users, organizations, and partners to have privileged and non privileged access to wallet funds.

# Findings

---

## [H-1] Attacker can extend a transaction they do not have the authority of

## Description

> The intended functionality of the ExtendTransaction instruction is to allow privileged user's (authorized signers and allowed unauthorized signers) the ability to extend a transaction. Under certain conditions, an attacker can successfully extend the transaction of another user.

## Proof of Issue

**File name: programs/cryptid/src/instructions/extend_transaction.rs**

**Line number: 140**

a) An attacker can call the extend instruction and supply the allow_unauthorized argument with `true`

```rust
    allow_unauthorized: bool,
```

**File name: programs/cryptid/src/instructions/extend_transaction.rs**

**Line number: 143**

b) If the transaction account has an `unauthorized_signer` value of `None` the authority check will be skipped

```rust
if let Some(unauthorized_signer) = ctx.accounts.transaction_account.unauthorized_signer {
        require_keys_eq!(
            ctx.accounts.authority.key(),
            unauthorized_signer,
            CryptidError::KeyMustBeSigner
        );

```

## Severity and Impact Summary

> Any Cryptid account with super-user middleware that creates a transaction account with no unauthorized signers is vulnerable to transaction account manipulation. This vulnerability is labelled high because an authorized Cryptid user can approve and execute a maliciously extended transaction that could cause severe damage.

## Recommendation

> The recommendation is to allow the user to pass allow_unauthorized as true if the transaction was already given an unauthorized signer during the propose transaction instruction.

---

## [M-1] Permissionless ApproveExecution instruction allows attackers to block another user's ExecuteTransaction instruction

## Description

> A permissionless instruction is when anyone on the Solana network can execute a transaction that interacts with the user's programs. In some cases, permissionless instructions can be harmless depending on the logic of the program in question. In the case of Cryptid, the permissionless ApproveExecution instruction can have negative effects on the functionality of core operations, such as the ExecuteTransaction instruction.

## Proof of Issue

**File name: programs/cryptid/src/instructions/approve_execution.rs**

**Line number: 7**

a) There are no constraints prohibiting an attacker from invoking the ApproveExecution instruction on a user's `transaction_account` causing the `approved_middleware` state to be `cleared`

```rust
pub struct ApproveExecution<'info> {
    pub middleware_account: Signer<'info>,
    #[account(
        mut,
        // ensure the transaction is not approved until it is ready to be approved, and is not executed
        constraint = transaction_account.state == TransactionState::Ready @ CryptidError::InvalidTransactionState,
    )]
    pub transaction_account: Account<'info, TransactionAccount>,
}
```

**File name: programs/cryptid/src/instructions/execute_transaction.rs**

**Line number: 165**

b) When the authorized user attempts to validate the transaction that an attacker approved, this require statement may cause the transaction to revert since the `approved_middlware` may not be the same as the `cryptid_account.middleware`. This would result in a successful denial of the `ExecuteTransaction` instruction.

```rust
require!(
        ctx.accounts.transaction_account.approved_middleware == cryptid_account.middleware,
        CryptidError::IncorrectMiddleware
    );

```

## Severity and Impact Summary

> Since the ApproveExecution instruction is permissionless, an attacker can clear the middleware approval state of an already approved transaction of a user. This prevents the user from executing their transaction. Executing transactions are a core function of Cryptid accounts. This finding is labeled as Medium instead of High because there are alternate ways for a user to execute instructions without the need of the ApproveExecute instruction. They can use the DirectExecute instruction instead.

## Recommendation

> A potential recommendation is to ONLY allow the proposer or permitted unauthorized signers the ability to approve the transaction. An alternate mitigation we discussed would include the Cryptid account having an ordered list of expected middleware to verify against. The last way to mitigate would be to advise users to close the transaction in question and to perform DirectExecutes in the event another user is attempting to block their transactions.

## [L-1]Attackers can block the execution of other user's transactions

## Description

> Whitelisted middleware accounts can be created by an attacker to block the execution of other users transactions.

##### Proof of Issue

**Filename:** _check_recipient/lbib.rs_

**Linenumber:** 16

```rust
pub fn create(
        ctx: Context<Create>,
        recipient: Pubkey,
        bump: u8,
        previous_middleware: Option<Pubkey>,
    ) -> Result<()> {
        ctx.accounts.middleware_account.recipient = recipient;
        ctx.accounts.middleware_account.authority = *ctx.accounts.authority.key;
        ctx.accounts.middleware_account.bump = bump;
        ctx.accounts.middleware_account.previous_middleware = previous_middleware;
        Ok(())
    }
```

a) An attacker can create a whitelisted middleware

**Filename:** _instructions/approve_execution.rs_

**Linenumber:** 35

```rust
ctx.accounts.transaction_account.approved_middleware =
        Some(*ctx.accounts.middleware_account.key);
```

b) An attacker can approve the execution of another users transaction account

**Filename:** _instructions/execute_transaction.rs_

**Linenumber:** 165

```rust
  require!(
        ctx.accounts.transaction_account.approved_middleware == cryptid_account.middleware,
        CryptidError::IncorrectMiddleware
    );
```

c) When an authorized user attempts to execute the transaction, it will revert due to the `approve_middleware` being incorrect

## Severity and Impact Summary

> Depending on the middleware configurations, many transactions can be blocked from performing transaction executions.

## Recommendation

> The two potential fixes could involve:

> - Tracking the whole chain of expected middleware accounts
> - Middleware accounts are required to perform checks before a CPI call takes place. For example, it could check that approve is not called via CPI if it is to an unrelated CryptidAccount.

## [INFO-1] The inability to modify Cryptid properties may create security risk

## Description

> Cryptid allows for super-user middleware accounts to approve transactions of unauthorized signers. When you create a Cryptid account, you specify the amount of super user middleware accounts you would like to have. After you create this Cryptid account, there is no way to edit or revoke these super-user middleware accounts.

## Proof of Issue

**File name: programs/cryptid/src/instructions/create_cryptid_account.rs**

**Line number: 40**

When using the CreateCyrptidAccount instruction, the Cryptid creator can provision an arbitrary amount of super-user middleware accounts. There are no other instructions that permit the modification or revocation of a superuser.

```rust
pub fn create_cryptid_account(
    ctx: Context<CreateCryptidAccount>,
    middleware: Option<Pubkey>,
    superuser_middlewares: Vec<Pubkey>,
    controller_chain: Vec<Pubkey>,
    index: u32,
    did_account_bump: u8,
) -> Result<()> {
    require_gt!(index, 0, CryptidError::CreatingWithZeroIndex);
    ctx.accounts.cryptid_account.middleware = middleware;
    ctx.accounts.cryptid_account.index = index;
    ctx.accounts.cryptid_account.superuser_middleware = superuser_middlewares;
```

## Severity and Impact Summary

> The more superusers that are created without the ability to be modified, the higher the risk that one of the super user's could become a malicious actor. This could happen in the form of a key compromise or good actor turned bad. In both of these scenarios, there is no way to revoke the super-user account of the malicious actor from the Cryptid account.

## Recommendation

> If Cryptid is intended for users and organizations to allow others the ability to have elevated abilities via a super-user middleware account , the recommendation is to implement a way to "burn" and recreate the account in the event of a compromise.
