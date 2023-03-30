## Overview

Soldid is a decentralized identity implementation deployed on Solana.

## [H-1] DID lockout can occur by using a malicious update instruction

## Description

> The intended functionality for a DID includes having no ability to lock out the account by removing the last verification method. This requirement check can be found in remove_verifcation_method.rs and set_vm_flags.rs.

## Proof of Issue

> In the update instruction, there are no checks to ensure that the DID account data still contains an authority verification method.

```rust

    pub fn update(
    ctx: Context<Update>,
    update_arg: UpdateArg,
    eth_signature: Option<Secp256k1RawSignature>,
) -> Result<()> {
    // Move the business logic DidAccount struct.
    let data = &mut ctx.accounts.did_data;
    if eth_signature.is_some() {
        data.nonce += 1;
    }

    data.set_services(update_arg.services, false)?;
    data.set_verification_methods(Vec::new(), update_arg.verification_methods)?;
    data.set_native_controllers(update_arg.native_controllers)?;
    data.set_other_controllers(update_arg.other_controllers)?;

    Ok(())
}

```

## Severity and Impact Summary

> Having the ability to lock out an account would prevent the DID account from operating in an intended manner. No user would be able to modify any methods of the DID since no permission verification method would exist.

## Recommendation

> Implement the did lockout require statement in the update function in update.rs or in the set_verification_method function in did_account.rs.

```rust
require!(
        data.has_authority_verification_methods(),
        DidSolError::VmCannotRemoveLastAuthority
    );
```

---

## [M-1] In the event of a key compromise, an attacker can remove the recovery method of the original DID owner

## Description

> A user who has 2 wallets can become locked out of their DID if an attacker compromises one of the user's wallets and removes the user's recovery abilities.

## Proof of Issue

> See the following scenario between Bob's wallet X and wallet Y. Wallet X is used to primarily interact with the DID and wallet y is used as a recovery key for the DID. If the Bob's wallet X is compromised by an attacker, then the attacker with control of wallet X can remove wallet Y's ability to recover the DID.

> This occurs when the attacker removes the verification method of wallet y.

```rust

pub fn remove_verification_method(
    ctx: Context<RemoveVerificationMethod>,
    fragment: String,
    eth_signature: Option<Secp256k1RawSignature>,
) -> Result<()> {
    let data = &mut ctx.accounts.did_data;
    if eth_signature.is_some() {
        data.nonce += 1;
    }

    let _ = data.remove_verification_method(&fragment);

    // prevent lockout
    require!(
        data.has_authority_verification_methods(),
        DidSolError::VmCannotRemoveLastAuthority
    );

    Ok(())
}

```

## Severity and Impact Summary

> Having non-recoverable options for a user's decentralized identity could result in a user losing their DID. This scenario could result in an attacker performing continued identity theft without the ability to be stopped.

## Recommendation

> The FYEO and Identity teams discussed two potential solutions. One of the proposed solutions we discussed was to modify the `capabilityInvocation` functionality and to require other verification keys to have fewer privileges. The second potential solution is to leverage a null recovery key that can never be removed. This would give the owner of a DID the ability to recover their DID in the event of a key compromise.

---

## [L-1] Missing check to ensure other controllers contain the proper DID syntax

## Description

> `sol:did` controllers must follow the correct DID syntax(`"did:" method-name ":" method-specific-id`) in order to conform to DID specifications. In the set_other_controllers function there is no check to ensure that the controller passed in, and follows the correct DID specification.

## Proof of Issue

> In the set_other_controllers function in did_account.rs there is one require statement. This statement checks to ensure that other controllers don't have the `sol:did` prefix. There is no check to ensure a proper did prefix

```rust
 require!(
            check_other_controllers(&self.other_controllers),
            DidSolError::InvalidOtherControllers
        );
```

```rust
pub fn check_other_controllers(controllers: &[String]) -> bool {
    controllers.iter().all(|did| !is_did_sol_prefix(did))
}

```

## Severity and Impact Summary

> The syntax of a did:documents must be followed, in order for did documents to be resolved properly. DID documents that contain controllers with improper syntax will be rejected during this resolution process.

## Recommendation

> Implement a `require` statement to ensure that the passed-in controller starts with the proper DID syntax.

---

## [INFO-1] Preventing the DID authority from being their own native controller deviates from the W3C DID specifications

## Description

> When setting a native controller, there is a required statement that prevents the initial DID authority from being its own DID controller. In the W3C DID specifications, the DID can be its own controller. This requirement in sol:did deviates from DID standards.

## Proof of Issue

```rust
require!(
            !self.native_controllers.contains(&own_authority),
            DidSolError::InvalidNativeControllers,
        );
```

## Severity and Impact Summary

> While this issue doesn't create breaking changes to the functionality of DID operations, it deviates from core DID architecture.

## Recommendation

> Remove the set controllers require statement to allow for a DID authority to become its own controller.

---

## [INFO-2] Controller functionality deviates from W3C specifications

## Description

> The [W3C specs](https://www.w3.org/TR/did-core/#dfn-did-controllers) state that a DID controller, "has the capability to make changes to a DID document". If a DID is set as a controller and it doesn't have the proper permissions, it will not have the authority to modify the DID document.

## Proof of Issue

> The `find_authority` function below is used to validate when a key is authorized to make changes to a DID. There are no checks to provide authority for controllers because there is no direct relationship between verification methods and controllers.

```rust
    pub fn find_authority(
        &self,
        key: &[u8],
        filter_types: Option<&[VerificationMethodType]>,
        filter_fragment: Option<&String>,
    ) -> Option<&VerificationMethod> {
        // msg!("Checking if key {:?} is an authority", key,);
        self.verification_methods(
            filter_types,
            Some(VerificationMethodFlags::CAPABILITY_INVOCATION),
            Some(key),
            filter_fragment,
        )
        .into_iter()
        .next()
    }
```

## Severity and Impact Summary

> For other controllers, this requirement cannot be fully satisfied, due to the inability to validate other controllers on chain. Any native controllers that are added without given `capabilityInvocation` privileges won't have the ability to modify DIDs

## Recommendation

> Make updates to the sol:did specifications, detailing the restrictions of other controllers. Native controllers will need to include some "relationship to verification" methods in order to fulfil controller requirements.

## [Link to Public Report](https://download-files.wixmp.com/ugd/156fab_93fe635a17c747cba376303c02773303.pdf?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1cm46YXBwOmU2NjYzMGU3MTRmMDQ5MGFhZWExZjE0OWIzYjY5ZTMyIiwic3ViIjoidXJuOmFwcDplNjY2MzBlNzE0ZjA0OTBhYWVhMWYxNDliM2I2OWUzMiIsImF1ZCI6WyJ1cm46c2VydmljZTpmaWxlLmRvd25sb2FkIl0sImlhdCI6MTY4MDE5MDc0MCwiZXhwIjoxNjgwMjI2NzUwLCJqdGkiOiI2NmUyNzZiMi1iNDkyLTQyNWItOTZiZC0yYzQ4YjI4NzA5NzIiLCJvYmoiOltbeyJwYXRoIjoiL3VnZC8xNTZmYWJfOTNmZTYzNWExN2M3NDdjYmEzNzYzMDNjMDI3NzMzMDMucGRmIn1dXSwiZGlzIjp7ImZpbGVuYW1lIjoiSWRlbnRpdHkgVGVjaG5vbG9naWVzIEluYy4gLSBTZWN1cml0eSBBc3Nlc3NtZW50IG9mIHRoZSBTb2xfRGlkIHYxLjAucGRmIiwidHlwZSI6ImF0dGFjaG1lbnQifX0.bFN4rSl6dbeXq2dRr5YlFVlaNJWMH_ket0ANtAY9Hcc)

## [Audit release details](https://www.gofyeo.com/post/fyeo-security-assessment-identity_com)
