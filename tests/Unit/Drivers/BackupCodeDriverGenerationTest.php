<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use Tests\TestCase;

/**
 * Generation-side unit tests for `BackupCodeDriver`.
 *
 * Exercises `generateSet()`, `generateSecret()`, and `hash()` — split from
 * `BackupCodeDriverTest` so the verify-path subject can stay under the
 * project's max-methods-per-class threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class BackupCodeDriverGenerationTest extends TestCase
{
    /**
     * `generateSet()` must produce exactly the configured number of codes and
     * each code must respect the configured length and alphabet.
     *
     * @return void
     */
    public function testGenerateSetReturnsConfiguredNumberOfCodes(): void
    {
        $driver = new BackupCodeDriver(
            codeLength: 8,
            alphabet: 'ABCDEF',
            codeCount: 5,
        );

        $codes = $driver->generateSet();

        self::assertCount(5, $codes);

        foreach ($codes as $code) {
            self::assertSame(8, strlen($code));
            self::assertMatchesRegularExpression('/^[ABCDEF]{8}$/', $code);
        }
    }

    /**
     * Generated codes within a single set must all be distinct so a lost code
     * does not invalidate another.
     *
     * @return void
     */
    public function testGenerateSetReturnsDistinctCodes(): void
    {
        $driver = new BackupCodeDriver(codeCount: 25);
        $codes  = $driver->generateSet();

        self::assertCount(25, $codes);
        self::assertSame($codes, array_values(array_unique($codes)));
    }

    /**
     * Passing an explicit positive `$count` overrides the configured default
     * for that single call — used by the manager-level
     * `Mfa::issueBackupCodes($count)` rotation API to mint a custom batch size
     * without rebinding the driver.
     *
     * @return void
     */
    public function testGenerateSetHonoursExplicitCountArgument(): void
    {
        $driver = new BackupCodeDriver(codeCount: 5);
        $codes  = $driver->generateSet(3);

        self::assertCount(3, $codes);
    }

    /**
     * A non-positive `$count` is a deployment-time bug, not a runtime
     * recoverable state — the driver throws so the misconfiguration surfaces in
     * the stack trace rather than silently returning an empty set.
     *
     * @return void
     */
    public function testGenerateSetThrowsWhenExplicitCountIsZero(): void
    {
        $driver = new BackupCodeDriver;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('at least 1');

        $driver->generateSet(0);
    }

    /**
     * `generateSet()` must reject a negative explicit count with a clear
     * `InvalidArgumentException` — a negative batch size cannot mint any codes
     * and would otherwise short-circuit silently.
     *
     * @return void
     */
    public function testGenerateSetThrowsWhenExplicitCountIsNegative(): void
    {
        $driver = new BackupCodeDriver;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('at least 1');

        $driver->generateSet(-3);
    }

    /**
     * `generateSecret()` must return a single plaintext code that matches the
     * configured alphabet and length.
     *
     * @return void
     */
    public function testGenerateSecretReturnsSinglePlaintextCode(): void
    {
        $driver = new BackupCodeDriver(codeLength: 12, alphabet: 'XYZ');
        $secret = $driver->generateSecret();

        self::assertIsString($secret);
        self::assertSame(12, strlen($secret));
        self::assertMatchesRegularExpression('/^[XYZ]{12}$/', $secret);
    }

    /**
     * `hash()` must be deterministic and equivalent to a raw SHA-256 digest of
     * the input.
     *
     * @return void
     */
    public function testHashIsDeterministicSha256(): void
    {
        $driver = new BackupCodeDriver;

        $first  = $driver->hash('STABLE-CODE');
        $second = $driver->hash('STABLE-CODE');

        self::assertSame($first, $second);
        self::assertSame(hash('sha256', 'STABLE-CODE'), $first);
    }
}
