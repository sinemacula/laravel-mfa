<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;

/**
 * What every `Reauthenticator` must guarantee, as an assertion: it answers
 * nothing, or a reauthentication with the first factor that it has just made,
 * bound to the identity and the application. A refusing default meets it; it is
 * not required to make a proof.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class ReauthenticatorContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The answer is `null`, or a first factor reauthentication of the identity
     * on the application, made within the last five minutes and not after now.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Reauthenticator  $reauthenticator
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    public static function assertNeverAnswersAProofItDidNotJustMake(Reauthenticator $reauthenticator, MultiFactorAuthenticatable $identity, string $application): void
    {
        $proof = $reauthenticator->reauthenticate($identity, $application);

        Assert::assertTrue(
            $proof === null || $proof->kind === ProofKind::FIRST_FACTOR_REAUTHENTICATION,
            'A reauthenticator must answer nothing or a first factor reauthentication.',
        );

        if ($proof === null) {
            return;
        }

        $now = CarbonImmutable::now();

        Assert::assertTrue(ProofOwner::of($identity)->owns($proof->binding), 'The reauthentication must be bound to the identity asked about.');
        Assert::assertSame($application, $proof->binding->application, 'The reauthentication must be bound to the application asked about.');
        Assert::assertTrue($proof->provedAt->lessThanOrEqualTo($now), 'The reauthentication must not be dated in the future.');
        Assert::assertTrue(
            $proof->provedAt->greaterThanOrEqualTo($now->subSeconds(ConfiguredFactorChangeGate::REAUTHENTICATION_MAX_AGE)),
            'The reauthentication must have just been made.',
        );
    }
}
