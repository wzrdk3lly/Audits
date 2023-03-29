# Overview

The PsyOptions Audit was performed by myself and a teamate. I will link my personal findings from the report in this repo and then post the Public Audit report with the aditional findings from my teammate.

# Findings

## [L-1] Unsafe Math

## Description

> on line 56:`one_in_aligned_decimals` and line 57: `one_in_oracle_decimals` the program performs exponential calculations that could potentially cause an overflow to occur. While the place of origin for `aligned_to_decimals` was not observed in the scope of Psyfi-Euros, there were no identified validation checks used for this value to prevent an overflow from occurring. The program consumed `exp` from Pyth without any validation checks on its value as well.

## Recommendation

> Use rusts checked_math library to prevent overflows

---

## [L-2] Use of Deprecated Pyth Client (Oracle)

## Description

> The Kudelski Security Team noticed that the cargo.toml:line 27 revealed the use of pyth-client version 0.2.2 which is a deprecated crate for the Pyth oracle. This means that the observed dependency for Pyth that was used for Psyfi-Euros during the code review is not supported by the original developers of that crate. The new Pyth sdk/crate implements additional functionality along with slight fixes.

## Recomendation

> Use the latest pyth client. It contains recent bug fixes and additonal security contstraints for the data feeds

---

### [Link to the Public Report](<https://1532366083-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F86y9tCw3TORp3IO5op2u%2Fuploads%2FCqCXj9VEtGSjdG97GNXS%2FPsyStake%20%26%20PsyFi%20Euros%20(July%2018%2C%202022).pdf?alt=media&token=b027a22c-cffc-4b6a-ac69-601a47713bda>)
