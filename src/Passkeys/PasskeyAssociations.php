<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use Illuminate\Database\UniqueConstraintViolationException;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Database\StorageTransaction;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The association records that make a passkey a factor. A mismatch with the
 * factor leaves it unusable, and a unique index associates a credential once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasskeyAssociations
{
    /**
     * Locked under the owner's lock. Matched again here, as a column's
     * collation may ignore case.
     *
     * @param  string  $credentialId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return ?\SineMacula\Laravel\Mfa\Models\PasskeyAssociation
     */
    public function ownedCredential(#[\SensitiveParameter] string $credentialId, ProofOwner $owner): ?PasskeyAssociation
    {
        $association = WriteConnection::query(PasskeyAssociation::query())
            ->where('credential_id_hash', CredentialId::hash($credentialId))
            ->where('authenticatable_type', $owner->type)
            ->where('authenticatable_id', $owner->key)
            ->lockForUpdate()
            ->first();

        return $association instanceof PasskeyAssociation
            && $association->credential_id        === $credentialId
            && $association->authenticatable_type === $owner->type
            && $association->authenticatable_id   === $owner->key
                ? $association
                : null;
    }

    /**
     * Whether anybody holds the credential. Unlocked, for checks made before
     * the factor state lock.
     *
     * @param  string  $credentialId
     * @return bool
     */
    public function exists(#[\SensitiveParameter] string $credentialId): bool
    {
        return self::find($credentialId, false) !== null;
    }

    /**
     * Unlocked: an association changes only with its factor, so a stale read
     * can only miss one.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return bool
     */
    public function associates(Factor $factor, ProofOwner $owner): bool
    {
        $id = LockedFactors::idOf($factor);

        if ($id === null) {
            return false;
        }

        $association = WriteConnection::query(PasskeyAssociation::query())->where('factor_id', $id)->first();

        return self::matches($factor, $owner, $association instanceof PasskeyAssociation ? $association : null);
    }

    /**
     * @param  string  $factorId
     * @return ?\SineMacula\Laravel\Mfa\Models\PasskeyAssociation
     */
    public function forFactor(string $factorId): ?PasskeyAssociation
    {
        $association = WriteConnection::query(PasskeyAssociation::query())
            ->where('factor_id', $factorId)
            ->lockForUpdate()
            ->first();

        return $association instanceof PasskeyAssociation ? $association : null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  string  $factorId
     * @param  string  $credentialId
     * @return \SineMacula\Laravel\Mfa\Models\PasskeyAssociation
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    public function associate(ProofOwner $owner, string $factorId, #[\SensitiveParameter] string $credentialId): PasskeyAssociation
    {
        $association = new PasskeyAssociation([
            'factor_id'            => $factorId,
            'authenticatable_type' => $owner->type,
            'authenticatable_id'   => $owner->key,
            'credential_id_hash'   => CredentialId::hash($credentialId),
            'credential_id'        => $credentialId,
        ]);

        $saved = self::save($association);

        if ($saved === null) {
            throw new OperationRefusedException(FailureReason::CREDENTIAL_ASSOCIATED, 'The credential is associated as a factor already.');
        }

        if (!$saved) {
            throw new WriteCanceledException('A model event cancelled the passkey association\'s save, so the passkey was not associated.');
        }

        return $association;
    }

    /**
     * @param  string  $factorId
     * @return void
     */
    public function forget(string $factorId): void
    {
        PasskeyAssociation::query()->where('factor_id', $factorId)->toBase()->delete();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  ?\SineMacula\Laravel\Mfa\Models\PasskeyAssociation  $association
     * @return bool
     */
    public static function matches(Factor $factor, ProofOwner $owner, ?PasskeyAssociation $association): bool
    {
        $id = $factor->getFactorIdentifier();

        if ($association === null || !(is_string($id) || is_int($id)) || $association->factor_id !== (string) $id) {
            return false;
        }

        return $association->authenticatable_type === $owner->type
            && $association->authenticatable_id   === $owner->key
            && $association->credential_id        === $factor->getCredentialReference();
    }

    /**
     * False when a model event cancels the save, null when another change
     * associated the credential first.
     *
     * A savepoint keeps a failed insert from aborting a PostgreSQL transaction,
     * and the locking re-read sees rows a MySQL snapshot would miss.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\PasskeyAssociation  $association
     * @return ?bool
     *
     * @throws \Illuminate\Database\UniqueConstraintViolationException
     * @throws \Throwable
     */
    private static function save(PasskeyAssociation $association): ?bool
    {
        try {
            return StorageTransaction::run(static fn (): bool => $association->save());
        } catch (UniqueConstraintViolationException $violation) {

            if (self::find($association->credential_id, true) === null) {
                throw $violation;
            }

            return null;
        }
    }

    /**
     * @param  string  $credentialId
     * @param  bool  $lock
     * @return ?\SineMacula\Laravel\Mfa\Models\PasskeyAssociation
     */
    private static function find(#[\SensitiveParameter] string $credentialId, bool $lock): ?PasskeyAssociation
    {
        $query = WriteConnection::query(PasskeyAssociation::query())->where('credential_id_hash', CredentialId::hash($credentialId));

        $association = ($lock ? $query->lockForUpdate() : $query)->first();

        // A column's collation may ignore case.
        return $association instanceof PasskeyAssociation && $association->credential_id === $credentialId ? $association : null;
    }
}
