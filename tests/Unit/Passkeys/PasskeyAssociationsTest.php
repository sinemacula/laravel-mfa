<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\TestCase;

/**
 * An association matches a passkey factor only when it belongs to the factor,
 * by its identifier as a string, to the factor's owner, and names the factor's
 * own credential.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyAssociations::class)]
final class PasskeyAssociationsTest extends TestCase
{
    /** @var string The owner's type. */
    private const string TYPE = 'App\Models\User';

    /** @var string The owner's key. */
    private const string KEY = '7';

    /** @var string The credential the factor and its association name. */
    private const string CREDENTIAL = 'Y3JlZGVudGlhbC0x';

    /**
     * A factor's own association matches it, whether its identifier is a string
     * or an integer.
     *
     * @return void
     */
    public function testTheFactorsOwnAssociationMatches(): void
    {
        self::assertTrue(PasskeyAssociations::matches($this->factor('factor-1'), $this->owner(), $this->association('factor-1')));
        self::assertTrue(PasskeyAssociations::matches($this->factor(5), $this->owner(), $this->association('5')));
    }

    /**
     * Another factor's association does not match, even with the same owner and
     * credential.
     *
     * @return void
     */
    public function testAnotherFactorsAssociationDoesNotMatch(): void
    {
        self::assertFalse(PasskeyAssociations::matches($this->factor('factor-1'), $this->owner(), $this->association('factor-2')));
    }

    /**
     * A factor with no usable identifier matches nothing, even an association
     * whose factor is the empty string its identifier would cast to.
     *
     * @return void
     */
    public function testAFactorWithoutAnIdentifierMatchesNothing(): void
    {
        self::assertFalse(PasskeyAssociations::matches($this->factor(null), $this->owner(), $this->association('')));
    }

    /**
     * No association, another owner or another credential matches nothing.
     *
     * @return void
     */
    public function testNoAssociationOrAnotherOwnerOrCredentialMatchesNothing(): void
    {
        self::assertFalse(PasskeyAssociations::matches($this->factor('factor-1'), $this->owner(), null));
        self::assertFalse(PasskeyAssociations::matches($this->factor('factor-1'), new ProofOwner(self::TYPE, '8'), $this->association('factor-1')));
        self::assertFalse(PasskeyAssociations::matches($this->factor('factor-1'), new ProofOwner('App\Models\Admin', self::KEY), $this->association('factor-1')));
        self::assertFalse(PasskeyAssociations::matches($this->factor('factor-1', 'b3RoZXI'), $this->owner(), $this->association('factor-1')));
    }

    /**
     * A passkey factor with the identifier and credential given.
     *
     * @param  mixed  $identifier
     * @param  string  $credential
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    private function factor(mixed $identifier, string $credential = self::CREDENTIAL): Factor
    {
        $factor = \Mockery::mock(Factor::class);

        $factor->shouldReceive('getFactorIdentifier')->andReturn($identifier);
        $factor->shouldReceive('getCredentialReference')->andReturn($credential);

        return $factor;
    }

    /**
     * The owner the associations are made for.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofOwner
     */
    private function owner(): ProofOwner
    {
        return new ProofOwner(self::TYPE, self::KEY);
    }

    /**
     * An unsaved association of the factor given with the owner's credential.
     *
     * @param  string  $factorId
     * @return \SineMacula\Laravel\Mfa\Models\PasskeyAssociation
     */
    private function association(string $factorId): PasskeyAssociation
    {
        return new PasskeyAssociation([
            'factor_id'            => $factorId,
            'authenticatable_type' => self::TYPE,
            'authenticatable_id'   => self::KEY,
            'credential_id_hash'   => hash('sha256', self::CREDENTIAL),
            'credential_id'        => self::CREDENTIAL,
        ]);
    }
}
