<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorStateCache;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Issues the current identity's backup codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecoveryCodeService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Drivers\DriverResolver  $drivers
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorService  $factors
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorStateCache  $cache
     */
    public function __construct(

        /** The container the event dispatcher is read from. */
        private Container $container,

        /** The resolver of the backup-code driver. */
        private DriverResolver $drivers,

        /** The resolver of the configured factor model. */
        private FactorService $factors,

        /** The per-request cache of the identity's factor state. */
        private FactorStateCache $cache,
    ) {}

    /**
     * Issue a fresh batch of backup codes for the current identity.
     *
     * Atomically replaces existing `backup_code` factors in the identity's
     * factor state transaction (see `Support\FactorStateTransaction`): prior
     * rows deleted, a fresh batch minted via `BackupCodeDriver`, one `Factor`
     * row per code persisted with the hashed value on `secret`. Returns the
     * plaintext set exactly once: the codes are NEVER recoverable after this
     * method returns.
     *
     * Each new factor dispatches `MfaFactorEnrolled`; the setup-state cache is
     * invalidated so `isSetup()` reflects the new batch immediately.
     *
     * No-op (returns `[]`) when no MFA-capable identity is resolvable.
     *
     * The backup-code driver is resolved from the given registry: the manager
     * the codes were issued through.
     *
     * @param  \Illuminate\Support\Manager  $registry
     * @param  ?int  $count
     * @return list<string>
     *
     * @throws \LogicException
     */
    public function issueBackupCodes(Manager $registry, ?int $count = null): array
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return [];
        }

        $driver = $this->drivers->driver($registry, BackupCodeDriver::NAME);

        if (!$driver instanceof BackupCodeDriver) {
            throw new \LogicException(sprintf('Driver [%s] must be a %s instance to issue backup codes.', BackupCodeDriver::NAME, BackupCodeDriver::class));
        }

        $codes      = $driver->generateSet($count);
        $modelClass = $this->factors->factorModel();

        // The rotation is a serialised change to the identity's factor state:
        // one transaction on the storage connection, holding the identity's
        // lock, so it commits or rolls back as one and a concurrent change for
        // the same identity waits for it.
        FactorStateTransaction::forIdentity($identity, new $modelClass, function () use ($identity, $driver, $codes, $modelClass): void {
            $this->rotateBackupCodeBatch($identity, $driver, $codes, $modelClass);
        });

        $this->cache->clear($identity);

        return $codes;
    }

    /**
     * Atomically replace the identity's existing backup-code factors with the
     * supplied freshly-minted batch. Runs inside the identity's factor state
     * transaction, opened by the caller: no overlap window where both old and
     * new codes would verify.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver  $driver
     * @param  list<string>  $codes
     * @param  class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $modelClass
     * @return void
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function rotateBackupCodeBatch(MultiFactorAuthenticatable $identity, BackupCodeDriver $driver, array $codes, string $modelClass): void
    {
        $morphType = CurrentIdentity::typeOf($identity);
        $morphId   = $identity->getAuthIdentifier();
        $events    = $this->container->make(Dispatcher::class);

        $modelClass::query()
            ->where('authenticatable_type', $morphType)
            ->where('authenticatable_id', $morphId)
            ->where('driver', BackupCodeDriver::NAME)
            ->delete();

        foreach ($codes as $code) {
            $factor   = new $modelClass;
            $relation = $factor->authenticatable();

            $factor->setAttribute($relation->getMorphType(), $morphType);
            $factor->setAttribute($relation->getForeignKeyName(), $morphId);
            $factor->setAttribute($factor->getDriverName(), BackupCodeDriver::NAME);
            $factor->setAttribute($factor->getSecretName(), $driver->hash($code));
            $factor->save();

            $events->dispatch(new MfaFactorEnrolled($identity, $factor, BackupCodeDriver::NAME));
        }
    }
}
