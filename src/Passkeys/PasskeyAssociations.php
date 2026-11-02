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
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Reads and writes the association records that make a passkey a factor.
 *
 * A passkey factor counts only with an association whose owner and credential
 * are the factor's own: the factor's credential reference and the association
 * are written and deleted together, in one factor state transaction, and any
 * mismatch between them leaves the factor unusable, as if it did not exist. A
 * credential is associated at most once, whoever holds it: the unique index on
 * its digest refuses a second association, a concurrent one included. Records
 * are read from the write connection. `ownedCredential()` names its owner in
 * the locking query, so another identity's association is never returned or
 * acted on, and `forFactor()` locks the association of a factor its caller
 * holds. The one locking read that names no owner is the lookup `save()` makes
 * after a unique violation. `exists()` and `associates()` take no lock, for the
 * checks made before the identity's factor state lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasskeyAssociations
{
    /**
     * The owner's association of the canonical credential id, or `null` when
     * the owner holds no association of it, locked as it is read under the
     * owner's factor state lock. The owner and the id are matched in the query
     * and again here, exactly, since a column's collation may ignore case.
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
     * Whether the canonical credential id is associated with anybody, read
     * without a lock, so it may be asked before the identity's factor state
     * lock is taken.
     *
     * @param  string  $credentialId
     * @return bool
     */
    public function exists(#[\SensitiveParameter] string $credentialId): bool
    {
        return self::find($credentialId, false) !== null;
    }

    /**
     * Whether the factor has an association that matches it (see `matches()`),
     * read without a lock, so it may be asked before the identity's factor
     * state lock is held. An association changes only with its factor, under
     * that lock, so what this reads cannot outlive the factor it was read for,
     * and a read older than the lock can only miss one, which counts as no
     * association.
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
     * The association of the factor, or `null` when it has none.
     *
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
     * Associate the canonical credential id with the owner's factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  string  $factorId
     * @param  string  $credentialId
     * @return \SineMacula\Laravel\Mfa\Models\PasskeyAssociation
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
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
            throw new WriteCancelledException('A model event cancelled the passkey association\'s save, so the passkey was not associated.');
        }

        return $association;
    }

    /**
     * Delete the factor's association, if it has one.
     *
     * @param  string  $factorId
     * @return void
     */
    public function forget(string $factorId): void
    {
        PasskeyAssociation::query()->where('factor_id', $factorId)->toBase()->delete();
    }

    /**
     * Whether the association belongs to the owner's factor and names the
     * factor's own credential.
     *
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
     * Save the association: `false` when a model event cancels it, and `null`
     * when a unique index refuses it and the credential turns out to be
     * associated, because another change associated it first and committed,
     * with this identity or another.
     *
     * The insert runs in a nested transaction, as a statement's failure aborts
     * the whole of a PostgreSQL transaction unless a savepoint contains it, and
     * a violation leaves it masked with its class unchanged. The credential is
     * looked up again with a locking read, as a plain read in a
     * MySQL transaction reads its snapshot, which can miss the row that was
     * committed after it. Finding it establishes the conflict, not which index
     * fired; finding nothing means the failure is something else, which is a
     * database error like any other and is thrown.
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
     * The association of the canonical credential id, read from the write
     * connection with or without a lock.
     *
     * @param  string  $credentialId
     * @param  bool  $lock
     * @return ?\SineMacula\Laravel\Mfa\Models\PasskeyAssociation
     */
    private static function find(#[\SensitiveParameter] string $credentialId, bool $lock): ?PasskeyAssociation
    {
        $query = WriteConnection::query(PasskeyAssociation::query())->where('credential_id_hash', CredentialId::hash($credentialId));

        $association = ($lock ? $query->lockForUpdate() : $query)->first();

        // The digest is compared by the database; the id itself is compared
        // here, exactly, since a column's collation may ignore case.
        return $association instanceof PasskeyAssociation && $association->credential_id === $credentialId ? $association : null;
    }
}
