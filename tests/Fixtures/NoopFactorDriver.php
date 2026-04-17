<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;

/**
 * No-op `FactorDriver` used by tests that need to register an extension whose
 * runtime behaviour does not matter.
 *
 * Used by the backup-code rotation regression to prove that
 * `Mfa::issueBackupCodes()` rejects an extension that is not a
 * `BackupCodeDriver` subclass — the rotation pipeline relies on
 * `BackupCodeDriver::hash()` and would otherwise silently corrupt state if the
 * consumer rebound the driver name to something incompatible.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class NoopFactorDriver implements FactorDriver
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    public function issueChallenge(Factor $factor): void
    {
        // Intentional no-op — fixture exists only to register a
        // driver name; runtime behaviour is irrelevant.
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        return false;
    }

    /**
     * @return ?string
     */
    public function generateSecret(): ?string
    {
        return null;
    }
}
