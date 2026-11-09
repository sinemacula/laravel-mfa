<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements\Concerns;

use Illuminate\Database\Eloquent\Collection;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;

/**
 * Arranges a person's sign-in and the requests a factor change gate is asked:
 * the person signs in afresh with the proofs given, and holds a confirmed
 * factor their TOTP step-ups are made with and, by default, another.
 *
 * @phpstan-require-extends \Tests\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ArrangesFactorChanges
{
    /** @var string The id of the factor the person's TOTP step-ups are made with. */
    protected const string STEPPED_UP_WITH = 'factor-totp';

    /** @var string The id of the person's other factor. */
    protected const string OTHER_FACTOR = 'factor-other';

    /**
     * The request for the person's change, from their sign-in, on the factors
     * given, or on their two confirmed factors.
     *
     * @formatter:off
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @param  ?string  $factorId
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  ?\Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest
     *
     * @formatter:on
     */
    protected function changeRequest(TestUser $user, FactorChange $change, ?string $factorId, ?Requirement $requirement = null, ?Collection $factors = null): FactorChangeRequest
    {
        $factors ??= new Collection([self::factorWith(self::STEPPED_UP_WITH), self::factorWith(self::OTHER_FACTOR)]);

        return new FactorChangeRequest($user, SignInProofs::APPLICATION, SignInProofs::SESSION, $change, $factors, $factorId, $requirement);
    }

    /**
     * A factor with the id and status, unsaved.
     *
     * @param  string  $id
     * @param  string  $status
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected static function factorWith(string $id, string $status = 'confirmed'): Factor
    {
        return (new Factor)->forceFill(['id' => $id, 'status' => $status]);
    }

    /**
     * Sign the person in afresh, recording the proofs given.
     *
     * @param  \Closure(\Tests\Fixtures\Requirements\SignInProofs): list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return \Tests\Fixtures\Identities\TestUser
     */
    protected function signInWith(\Closure $proofs): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->firstOrCreate(['email' => 'changing@example.test']);

        $this->actingAs($user);

        $store = $this->container()->make(ProofStore::class);

        $store->begin($user, SignInProofs::APPLICATION, SignInProofs::SESSION);

        foreach ($proofs(SignInProofs::of($user)) as $proof) {
            $store->record($user, $proof);
        }

        return $user;
    }
}
