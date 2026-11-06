# Changelog

## 1.0.0 (2026-11-06)


### ⚠ BREAKING CHANGES

* store delivered codes as keyed hashes and cap their delivery ([#60](https://github.com/sinemacula/laravel-mfa/issues/60))
* count attempts, lock out and disable at the failure ceiling ([#58](https://github.com/sinemacula/laravel-mfa/issues/58))
* verify TOTP with an RFC 6238 implementation of our own ([#56](https://github.com/sinemacula/laravel-mfa/issues/56))
* reshape the factor schema, identity contract and events ([#54](https://github.com/sinemacula/laravel-mfa/issues/54))
* configure applications and validate bounds at boot ([#53](https://github.com/sinemacula/laravel-mfa/issues/53))
* add the seam contracts and the storage transaction ([#52](https://github.com/sinemacula/laravel-mfa/issues/52))
* add the assurance and proof vocabulary ([#51](https://github.com/sinemacula/laravel-mfa/issues/51))

### Features

* 1.0 release — driver-based MFA for Laravel ([#1](https://github.com/sinemacula/laravel-mfa/issues/1)) ([af6d486](https://github.com/sinemacula/laravel-mfa/commit/af6d486206837d28d027ef1926aa3d3c139bb0a6))
* add the assurance and proof vocabulary ([#51](https://github.com/sinemacula/laravel-mfa/issues/51)) ([0bd3155](https://github.com/sinemacula/laravel-mfa/commit/0bd31559b84425c41c2a73927991387e477f4f1f))
* add the factor change seams an authentication layer binds ([#86](https://github.com/sinemacula/laravel-mfa/issues/86)) ([ab91dad](https://github.com/sinemacula/laravel-mfa/commit/ab91dada7958b6d751834be7146d9fa72f104716))
* add the seam contracts and the storage transaction ([#52](https://github.com/sinemacula/laravel-mfa/issues/52)) ([6f5b175](https://github.com/sinemacula/laravel-mfa/commit/6f5b175232b0ed02fd2955cc9f21fc4fde9d3c9b))
* compose requirements and judge freshness per operation ([#63](https://github.com/sinemacula/laravel-mfa/issues/63)) ([759e52e](https://github.com/sinemacula/laravel-mfa/commit/759e52ebea129c1c641cf917f31eebc073e35753))
* configure applications and validate bounds at boot ([#53](https://github.com/sinemacula/laravel-mfa/issues/53)) ([16ae14b](https://github.com/sinemacula/laravel-mfa/commit/16ae14bf7eb0bc89e9e214cadc02a3ad646ca539))
* count attempts, lock out and disable at the failure ceiling ([#58](https://github.com/sinemacula/laravel-mfa/issues/58)) ([e228584](https://github.com/sinemacula/laravel-mfa/commit/e2285843d6f06013cf420aaadc798331449f0d02))
* decide which factors combine and what assurance they give ([#55](https://github.com/sinemacula/laravel-mfa/issues/55)) ([96e5413](https://github.com/sinemacula/laravel-mfa/commit/96e5413d3f40b51d913f4b1de89ab3a31454dbe5))
* enrol factors through a granted, confirmed flow ([#66](https://github.com/sinemacula/laravel-mfa/issues/66)) ([0bf1aea](https://github.com/sinemacula/laravel-mfa/commit/0bf1aea0e313b96e25c5e28413b65f6d5ed09141))
* expose testing helpers and translate every message ([#69](https://github.com/sinemacula/laravel-mfa/issues/69)) ([4bf9a5d](https://github.com/sinemacula/laravel-mfa/commit/4bf9a5dfaea455a342c885f60a7f1e60b0a9a3b1))
* finish the manager surface and scope route binding ([#70](https://github.com/sinemacula/laravel-mfa/issues/70)) ([3a1d672](https://github.com/sinemacula/laravel-mfa/commit/3a1d67202f235c5ce3d24caa6c6927725f51fad0))
* gate requests on the whole requirement through one middleware ([#68](https://github.com/sinemacula/laravel-mfa/issues/68)) ([ad23912](https://github.com/sinemacula/laravel-mfa/commit/ad23912639983f19281725d8d43a49b838c309fa))
* generate, store and redeem recovery codes as a set ([#62](https://github.com/sinemacula/laravel-mfa/issues/62)) ([e145ec9](https://github.com/sinemacula/laravel-mfa/commit/e145ec96cf51e352660ccb8cb8319b0e5e69aa72))
* give every seam a fail-closed default and add passkeys ([#64](https://github.com/sinemacula/laravel-mfa/issues/64)) ([713632d](https://github.com/sinemacula/laravel-mfa/commit/713632dd477379fef7815bda5763fadb731f36e3))
* hand code senders a neutral code message ([#94](https://github.com/sinemacula/laravel-mfa/issues/94)) ([ca92e07](https://github.com/sinemacula/laravel-mfa/commit/ca92e0769ecef46712a975a6c3e0fc651561d79f))
* hand the caller and its same-site facts to the pending completion ([#105](https://github.com/sinemacula/laravel-mfa/issues/105)) ([3dca70d](https://github.com/sinemacula/laravel-mfa/commit/3dca70d9b17f4b6e57fc649dec2b10545a9f4f38))
* hand the event context resolver the sign-in an event is about ([#106](https://github.com/sinemacula/laravel-mfa/issues/106)) ([9f59ae0](https://github.com/sinemacula/laravel-mfa/commit/9f59ae07df69a53cafcc98261ae009fc05f1a3f5))
* harden the package for long-running processes and database failure ([#71](https://github.com/sinemacula/laravel-mfa/issues/71)) ([b8fa11a](https://github.com/sinemacula/laravel-mfa/commit/b8fa11a9c90387a8c9dbf63312c7810fc4e2566c))
* judge the session again after every factor change through the session transition ([#87](https://github.com/sinemacula/laravel-mfa/issues/87)) ([0aba195](https://github.com/sinemacula/laravel-mfa/commit/0aba195a0117e14f7be0a8b29580013b4d4ae87b))
* keep a factor's lockout deadline on its own row ([#77](https://github.com/sinemacula/laravel-mfa/issues/77)) ([4777456](https://github.com/sinemacula/laravel-mfa/commit/4777456b2b27a65a5b95f512e6ae894d6861b9fd))
* keep proofs in a session store bound to the sign-in ([#59](https://github.com/sinemacula/laravel-mfa/issues/59)) ([ce8e535](https://github.com/sinemacula/laravel-mfa/commit/ce8e5356c963b74851571c065a2ced5d7387ccd3))
* keep secrets out of output, logs and traces ([#57](https://github.com/sinemacula/laravel-mfa/issues/57)) ([0af0ef0](https://github.com/sinemacula/laravel-mfa/commit/0af0ef05d760f95de2159e2530d6675f87dba9a6))
* let a bound resolver say whether an identity is active ([#102](https://github.com/sinemacula/laravel-mfa/issues/102)) ([396db95](https://github.com/sinemacula/laravel-mfa/commit/396db95a2fd6b5522b7ee64881446a2484025439))
* let an application resolver name the application through a guard ([#104](https://github.com/sinemacula/laravel-mfa/issues/104)) ([054a782](https://github.com/sinemacula/laravel-mfa/commit/054a7822fdc8f4fbc8a693d7e833eaa6ff2d8507))
* let the proof store kit arrange proofs through another layer ([#97](https://github.com/sinemacula/laravel-mfa/issues/97)) ([c18cd13](https://github.com/sinemacula/laravel-mfa/commit/c18cd13deda3f307b70ea0c5c80a6fe897088baa))
* let the proof store kit run on an authentication layer's sessions ([#93](https://github.com/sinemacula/laravel-mfa/issues/93)) ([00e38ed](https://github.com/sinemacula/laravel-mfa/commit/00e38ed0b2627c90bcdb486e9fad2a3e92791af4))
* list, remove, reset, unlock and prune factors ([#67](https://github.com/sinemacula/laravel-mfa/issues/67)) ([a68831d](https://github.com/sinemacula/laravel-mfa/commit/a68831d1deaeef42ecbe9df0c5f963f69506c70d))
* name the lockout a counted failure caused ([#103](https://github.com/sinemacula/laravel-mfa/issues/103)) ([10a76f4](https://github.com/sinemacula/laravel-mfa/commit/10a76f4db4a5bc6d8ad81d6496311d1455e1f1cd))
* raise the default recovery code length to 13 characters ([#76](https://github.com/sinemacula/laravel-mfa/issues/76)) ([fd53617](https://github.com/sinemacula/laravel-mfa/commit/fd53617d1a4d15efe3d4915e167b660cdc6a21e2))
* reshape the factor schema, identity contract and events ([#54](https://github.com/sinemacula/laravel-mfa/issues/54)) ([cef9575](https://github.com/sinemacula/laravel-mfa/commit/cef95755aa4c0eb66f842606ef68f6e77042c46c))
* say whether a verified proof refreshes multifactor ([#98](https://github.com/sinemacula/laravel-mfa/issues/98)) ([1789d3f](https://github.com/sinemacula/laravel-mfa/commit/1789d3f301ae35c549ded46028b555b816aa6c31))
* store delivered codes as keyed hashes and cap their delivery ([#60](https://github.com/sinemacula/laravel-mfa/issues/60)) ([95c22e1](https://github.com/sinemacula/laravel-mfa/commit/95c22e170ace0879adf9608aa5761f3696c97ab9))
* take the caller as plain values on every action ([#100](https://github.com/sinemacula/laravel-mfa/issues/100)) ([9920d9a](https://github.com/sinemacula/laravel-mfa/commit/9920d9a9548a036844bd365d26b6dbf3a7bfd152))
* verify factors, codes and recovery codes through one flow ([#65](https://github.com/sinemacula/laravel-mfa/issues/65)) ([6e2554e](https://github.com/sinemacula/laravel-mfa/commit/6e2554eaa05f474bfcfe02390ad445bd70738a32))
* verify TOTP with an RFC 6238 implementation of our own ([#56](https://github.com/sinemacula/laravel-mfa/issues/56)) ([e6ddd14](https://github.com/sinemacula/laravel-mfa/commit/e6ddd14dbf3366c41629e313b4cfd31ca3e70be2))


### Bug Fixes

* bind every default only when nothing is bound yet ([#92](https://github.com/sinemacula/laravel-mfa/issues/92)) ([abc4e52](https://github.com/sinemacula/laravel-mfa/commit/abc4e522a9d4acb289855299a17b24234efccd92))
* keep a proof only once its verification commits ([#61](https://github.com/sinemacula/laravel-mfa/issues/61)) ([b07b434](https://github.com/sinemacula/laravel-mfa/commit/b07b4344dc169dca89788b7456f0facec26460bd))
* log a value that refuses to be logged as its class alone ([#101](https://github.com/sinemacula/laravel-mfa/issues/101)) ([f764d6b](https://github.com/sinemacula/laravel-mfa/commit/f764d6b6b444d2636c31f112318ec77d7229e5bb))
