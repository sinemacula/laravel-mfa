# Project Overview

`sinemacula/laravel-mfa` - Driver-based multi-factor authentication for Laravel. Supports TOTP, email codes, SMS codes,
and backup codes out of the box, with a pluggable driver API for custom factor types.

- **Namespace:** `SineMacula\Laravel\Mfa`
- **Source:** `src/`
- **Type:** Library (Composer package)
- **PHP 8.3+ / Laravel 12 / 13**

## Architecture

Standalone MFA layer. Sibling IAM packages (Authentication, SSO, Authorization, Audit Log, IAM umbrella) live in their
own repositories - this package has zero runtime dependencies on them.

Core model: **MfaManager** (Laravel Manager pattern) dispatches verification to pluggable **FactorDriver**
implementations. Middleware enforces MFA on routes; exceptions carry structured factor data for the consuming app to
render. The package depends only on Laravel's standard `Authenticatable` contract, so it composes with any auth stack.

## Commands

```bash
composer install                          # Install dependencies
composer check                            # Static analysis via qlty (PHPStan 8, PHP-CS-Fixer, CodeSniffer)
composer check -- --all --no-cache --fix  # Full check with auto-fix
composer format                           # Format code via qlty

# Testing
composer test                             # All suites in parallel (Paratest)
composer test:coverage                    # All suites with clover coverage
composer test:unit                        # Unit suite only
composer test:feature                     # Feature suite only
composer test:integration                 # Integration suite only
composer test:performance                 # Performance budget suite (serial)
composer test:mutation                    # Scoped mutation gate (85% MSI)
composer test:mutation:full               # Full mutation suite (no thresholds)

# Benchmarks
composer bench                            # PHPBench hot-path benchmarks
composer bench:ci                         # PHPBench with CI artifact dump

# Single test file or method
vendor/bin/phpunit tests/Unit/SomeTest.php
vendor/bin/phpunit --filter testMethodName tests/Unit/SomeTest.php
```

## Conventions

- Default branch: `master`. Branch prefixes: `feature/`, `bugfix/`, `hotfix/`, `refactor/`, `chore/`
- Use Conventional Commits
- Never mention AI tools in commit messages or code comments
- PHPStan level 8 (strict). All code must pass `composer check` before handoff
- Run `composer test` before handoff when executable PHP changes are made
- Keep changes minimal and scoped to the request; avoid unrelated refactors
- Do not change static analysis or formatting configuration without approval

## Code style rules

- Using traits must be single-line: `use SomeTrait, AnotherTrait;` — never multi-line
- Multiline docblocks wrap at 80 characters; use the full 80 where the content allows
- Do NOT mention request / feature / backlog item numbers (e.g. `B-07`, `B-09`) in docblocks,
  comments, or code. The backlog is the correct place for those references — source lives without them.
- After every implementation piece: run `composer format`, then `composer check`, then commit.
- After every committed piece: spawn a fresh review subagent to independently audit and report issues.
  Address valid findings before moving on.
