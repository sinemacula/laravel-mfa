# Budgets and Benchmarks

## Purpose

This note records what the package promises about its own cost and how that is checked: the query budgets, which pin
every statement a path makes and fail the build when one appears or goes away, and the benchmarks, which measure time
and assert nothing about it.

## Invariants

- A budget is exact. `assertQueryBudget()` takes a number of reads and a number of writes and requires both, because an
  upper bound would hide a statement that went away and let the ledger beside it drift.
- Statements are recorded from every connection, and only while the path under test runs, so a fixture's statements are
  never counted. A `select` is a read and an `insert`, `update` or `delete` is a write. Anything else fails the test
  with every statement listed, so a statement nobody has classified is never counted as either.
- A budget also asserts its path's outcome, so it never holds for the wrong branch: a hit is verified, a miss answers
  `invalid_code`, a locked factor answers `locked`.
- Every budget has a ledger beside it, naming each statement it counts. The ledger is read from the SQL the path logs,
  never estimated, and it changes in the same commit as the number.
- The budgets run on SQLite, MySQL and PostgreSQL. The package has no statement that depends on the driver, so one set
  of numbers holds for all three, and the MySQL and PostgreSQL steps in CI are what prove that.
- A budget counts the package's own statements. What an adapter behind a seam runs, a passkey gateway or a completion
  for a pending session, is outside it.
- No test asserts on wall-clock time, and a benchmark's result never fails the build. A benchmark's fixture does: every
  bench proves at set-up that the path reaches the outcome it is named for, through `BenchOutcome::assert()`, so a
  fixture that drifts fails the run instead of timing a refusal in the path's place.
- Results are not published in these notes, as they belong to a machine and a moment. What the notes state is how a cost
  scales.

## Success Path

- The verification budgets cover a TOTP hit, in an address's first window and in a later one, a miss and a locked
  factor; a delivered code's send, hit and miss through the package's own `ChallengeGateway`; a recovery code's hit and
  miss; a passkey's hit through a fake gateway; and a TOTP hit on a pending session.
- The enrolment budgets cover a TOTP and a delivered start, a first factor's and a later factor's confirmation, and a
  wrong code.
- The gate's budget covers a request the `mfa` middleware lets on, in `always` mode, with the first factor declared and
  with it recorded. It only reads.
- `VerificationBench` times a whole `Mfa::verify()`, hit and miss, for a TOTP code, a delivered code and a recovery
  code, with the statements, the locks and the evaluation included. It runs on `BenchApplication`, a Testbench
  application with the package's provider, in-memory SQLite and an array session, as the default seams need the session
  guard, the session store and the auth stack, and a hand-built container would drift from what the budgets run.
- A verification uses up its code or counts its failure, so each subject runs once in a process. PHPBench starts one
  process for each iteration, which gives each a fresh database. `VerificationBenchHarness` seeds two people with their
  own sign-ins, factors and addresses, so every limiter key is separate; it runs the branch on the first, which warms
  the path and proves its outcome, and times the same call for the second, so the call makes exactly the statements the
  budget's ledger counts for that branch. For a TOTP or a recovery code those are an address's first window; a delivered
  code's send has already begun the window, so its call takes the slot by the update alone. The application is in the
  budgets' requirement mode, `never`, so a hit evaluates the same requirement they do.
- `RecoveryCodeBench`, `TotpDriverBench`, `CombinationEvaluationBench`, `DeliveredCodeHashBench` and
  `FactorSummaryBench` time their parts with no database. `RequirementCheckBench` times `ProofRequirementCheck::check()`
  with no database and the `mfa` middleware on `BenchApplication`; the middleware only reads, so it is measured over
  ordinary revolutions.
- A recovery code's cost is per unused code and does not depend on position. `RecoveryCodeBench` shows it at bcrypt's
  cheapest cost across full, partly used and empty sets, and at the framework's default cost for the first, the last and
  no match in a full set and no match in a partly used one. A redemption's time is about one password check for each
  unused code, and its statements do not change with that count, as the budgets pin.

## Failure / Edge Cases

- A budget that fails lists every statement the path made, with its connection, so a change can be read off the failure.
- The statements of a confirmation's recovery set grow with `recovery_codes.count`, as the set is inserted row by row:
  one write for each code, with the reads unchanged. A bulk insert would skip the models' events and the write guard.
- An address's first window takes one write more than a later one: the update finds no row, then the insert makes it.
- Raising a whole-path subject's revolutions, or warming it up, from the command line throws rather than timing a used
  fixture. The guard is held outside anything set-up resets, so running iterations in one process fails the same way.
- `VerificationBench`'s timings are on SQLite with bcrypt at cost 4, the application booted and the path warmed outside
  the timing. A networked database and the application's hashing cost dominate them, so they show changes in the
  package's path and are not its isolated overhead.
- `TotpDriverBench`'s factor is not an Eloquent one and has nowhere to record a step, so both its subjects answer
  `INVALID`: it times the comparison of the window with a code in it and a code outside it. `ACCEPTED`, with the
  compare-and-set, is timed only by `VerificationBench`.
- A timing has no opcache on the command line and shares its machine, so only a large or repeated change means anything.
  The scheduled CI job uploads the report and compares nothing.

## Implementation Anchors

- `tests/Performance/PerformanceContractTestCase.php`: `assertQueryBudget()`, the classification and the listing.
- `benchmarks/Support/BenchOutcome.php`: `assert()`.
- `benchmarks/Support/BenchApplication.php`: `create()`, the frozen clock, the people and factors a bench seeds.
- `benchmarks/Support/VerificationBenchHarness.php`: the branches, the warm-up and the once-only `run()`.
- `benchmarks/Support/BenchProofs.php`: the proof sets the combination and requirement benches evaluate.
- `benchmarks/Runtime/VerificationBench.php`, `RecoveryCodeBench.php`, `TotpDriverBench.php`,
  `CombinationEvaluationBench.php`, `RequirementCheckBench.php`, `DeliveredCodeHashBench.php` and
  `FactorSummaryBench.php`.

## Authoritative Tests

- `tests/Performance/QueryBudgetContractTest.php`
  `testAStatementNobodyClassifiedFails`
- `tests/Performance/QueryBudgetContractTest.php`
  `testOnlyThePathIsCounted`
- `tests/Performance/VerificationQueryBudgetTest.php`
  `testATotpHitInTheAddressesFirstWindow`
- `tests/Performance/VerificationQueryBudgetTest.php`
  `testATotpHitInALaterWindow`
- `tests/Performance/VerificationQueryBudgetTest.php`
  `testARecoveryCodeHit`
- `tests/Performance/EnrollmentQueryBudgetTest.php`
  `testAFirstFactorConfirmation`
- `tests/Performance/RequirementGateQueryBudgetTest.php`
  `testAPassingRequestOnADeclaredFirstFactor`

## Change Triggers

Update this note when any of the following change:

- what a budget counts, how a statement is classified, or the drivers the budgets run on
- the branches a budget or a whole-path bench covers
- the application the whole-path benches run on, or what is timed outside its set-up
- how a recovery code's cost scales, or how a set is inserted
- the rule that a benchmark's result fails nothing
