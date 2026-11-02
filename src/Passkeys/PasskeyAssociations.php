<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Reads and writes the association records that make a passkey a factor.
 *
 * A passkey factor counts only with an association whose owner and credential
 * are the factor's own: the factor's credential reference and the association
 * are written and deleted together, in one factor state transaction, and any
 * mismatch between them leaves the factor unusable, as if it did not exist.
 * Records are read from the write connection, with a locking read, so a read
 * made inside a change sees what that change and any committed one left.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasskeyAssociations
{
    /**
     * The association of the canonical credential id, whoever holds it, or
     * `null` when it is associated with nobody.
     *
     * @param  string  $credentialId
     * @return ?\SineMacula\Laravel\Mfa\Models\PasskeyAssociation
     */
    public function forCredential(#[\SensitiveParameter] string $credentialId): ?PasskeyAssociation
    {
        $association = WriteConnection::query(PasskeyAssociation::query())
            ->where('credential_id_hash', CredentialId::hash($credentialId))
            ->lockForUpdate()
            ->first();

        // The digest is compared by the database; the id itself is compared
        // here, exactly, since a column's collation may ignore case.
        return $association instanceof PasskeyAssociation && $association->credential_id === $credentialId ? $association : null;
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

        if (!$association->save()) {
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

        return $association !== null
            && (is_string($id) || is_int($id))
            && $association->factor_id            === (string) $id
            && $association->authenticatable_type === $owner->type
            && $association->authenticatable_id   === $owner->key
            && $association->credential_id        === $factor->getCredentialReference();
    }
}
