<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;

/**
 * `EloquentFactor` fixture that is NOT an Eloquent Model — exercises the
 * backup-code driver's non-Model atomic-consume early-return.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class NonModelEloquentBackupCodeFactor extends AbstractEloquentFactorStub
{
    /**
     * Capture the seeded secret value.
     *
     * @param  ?string  $secret
     * @return void
     */
    public function __construct(

        /** Stored backup-code secret hash. */
        #[\SensitiveParameter]
        private readonly ?string $secret,

    ) {}

    /**
     * Return the fixture's fixed factor identifier.
     *
     * @return mixed
     */
    public function getFactorIdentifier(): mixed
    {
        return 'non-model';
    }

    /**
     * Return the backup-code driver name.
     *
     * @return string
     */
    public function getDriver(): string
    {
        return BackupCodeDriver::NAME;
    }

    /**
     * Return the seeded secret hash.
     *
     * @return ?string
     */
    public function getSecret(): ?string
    {
        return $this->secret;
    }
}
