# Changelog

## 0.1.0 (2026-11-21)

First release. Driver-based multi-factor authentication for Laravel: factors, recovery codes, step-up verification and
a route gate for any guard, with assurance on the scale NIST SP 800-63B-4 defines.

### Features

* TOTP, email code, SMS code and passkey factors behind drivers, with TOTP verified by an RFC 6238 implementation of the package's own
* enrolment through a granted, confirmed flow, and factors listed, removed, reset, unlocked and pruned
* recovery codes generated, stored and redeemed as a set
* one verification flow for factors, codes and recovery codes, with attempt counting, lockout and a failure ceiling
* the assurance a session's proofs add up to, from which factors combine and what each gives
* requirements composed per operation, with freshness judged for each
* one middleware that gates requests on the whole requirement, and a step-up refusal for callers without a request
* delivered codes stored as keyed hashes, with caps on how often they are sent
* seams with fail-closed defaults for an authentication layer: the proof store, session transitions, factor change gates, the passkey gateway and pending completion
* per-application configuration validated at boot, and `mfa:check`
* secrets kept out of output, logs and traces, and state kept safe in long-running processes
* testing helpers, a contract test kit for each seam and translatable messages
