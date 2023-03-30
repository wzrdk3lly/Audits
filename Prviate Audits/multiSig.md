# Overview

This MultiSig audit was for a GameFi protocol on Solana.

\*Due to MSA requirements I will not include detailed findings. I will only include Descriptions of how the attack occurred.

# Findings

---

## [H-1] MultiSig wallet allows duplicated key pairs

## Description

Duplicated key pairs will allow a user to bypass the threshold set because the threshold functionality assumes each owner to be a unique key pair. If the threshold set is 2 of 3 signatures and 2 of the key pairs are duplicated then a key owner would be able to bypass this requirement.

## [H-2] The creator of the smart wallet can set only 1 owner

## Description

The intended functionality of the multisig is to REQUIRE an m of n signature threshold with m and n being greater than 1.

## [H-3] Configuring the wallet with a higher threshold than total users can lead to wallet lockout

## Description

When using an m-n process for multisigs, it's important to validate that m is not greater than the amount of available signers. For instance, if I create a multisig with 2 owners requiring a 5 of 10 threshold, there needs to be a check to ensure the amount of owners is greater than or equal to 5. Without this check, the 2 owners will never be able to successfully approve transactions.
