<?php

declare(strict_types = 1);

namespace Tests\Feature\Factors;

use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Concerns\ResolvesFactorRouteBinding;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorRouteBinding;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;
use Tests\Fixtures\Identities\ScopedFactorOwner;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * An implicitly bound factor through real routes: the access credential's
 * identity, or a pending credential's when the request carries one that allows
 * an action naming an existing factor; nobody else's factor, and nothing for a
 * credential that does not validate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRouteBinding::class)]
#[CoversClass(CallerContextResolver::class)]
#[CoversTrait(ResolvesFactorRouteBinding::class)]
final class FactorRouteBindingTest extends TestCase
{
    use ArrangesVerification;

    /**
     * Arrange the application, and the routes an application would declare.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        Route::middleware(['auth', SubstituteBindings::class])->group(static function (): void {
            Route::get('access/factors/{factor}', static fn (Factor $factor): string => $factor->id);
        });

        Route::middleware(SubstituteBindings::class)->group(static function (): void {
            Route::get('factors/{factor}', static fn (Factor $factor): string => $factor->id);
            Route::get('labeled/{factor:label}', static fn (Factor $factor): string => $factor->id);

            Route::post('factors/{factor}/verify', static function (Factor $factor): string {
                $result = Mfa::verify(Submission::factor($factor->getFactorIdentifier(), '000000'));

                return $result->reason->value ?? 'verified';
            });

            Route::get('owners/{owner}/factors/{factor}', static fn (ScopedFactorOwner $owner, Factor $factor): string => $factor->id)
                ->scopeBindings();
        });
    }

    /**
     * Behind `auth`, the signed-in person's factor binds.
     *
     * @return void
     */
    public function testTheAccessCredentialBindsItsOwnFactor(): void
    {
        $factor = $this->totpFactor($this->signedInPerson());

        $this->getJson('access/factors/' . $factor->id)->assertOk()->assertSee($factor->id);
    }

    /**
     * Another person's factor is the `404` of a factor that does not exist.
     *
     * @return void
     */
    public function testAnotherPersonsFactorIsNotFound(): void
    {
        $this->signedInPerson();

        $theirs = $this->totpFactor($this->person('other@example.test'));

        $this->getJson('access/factors/' . $theirs->id)->assertNotFound();
        $this->getJson('access/factors/01JUNKNOWNFACTOR0000000000')->assertNotFound();
    }

    /**
     * Nobody signed in is stopped by `auth` before the binding, and with no
     * `auth` on the route the binding itself finds nothing.
     *
     * @return void
     */
    public function testAnUnauthenticatedRequestBindsNothing(): void
    {
        $factor = $this->totpFactor($this->person());

        $this->getJson('access/factors/' . $factor->id)->assertUnauthorized();
        $this->getJson('factors/' . $factor->id)->assertNotFound();
    }

    /**
     * A malformed id is the `404` it would be for the caller's own, not an
     * error.
     *
     * @return void
     */
    public function testAMalformedIdIsNotFound(): void
    {
        $this->signedInPerson();

        $this->getJson('access/factors/not-a-ulid')->assertNotFound();
    }

    /**
     * A custom key in the route still binds, within the caller.
     *
     * @return void
     */
    public function testACustomKeyInTheRouteBinds(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['label' => 'phone']);

        $this->getJson('labeled/phone')->assertOk()->assertSee($factor->id);
        $this->getJson('labeled/tablet')->assertNotFound();
    }

    /**
     * Rows of the actions a pending credential allows and whether its person's
     * factor binds.
     *
     * @return iterable<string, array{list<\SineMacula\Laravel\Mfa\Enums\PendingAction>, bool}>
     */
    public static function pendingActions(): iterable
    {
        yield 'listing factors' => [[PendingAction::LIST_FACTORS], true];
        yield 'sending a code' => [[PendingAction::SEND_CODE], true];
        yield 'verifying' => [[PendingAction::VERIFY], true];
        yield 'bootstrap only' => [[PendingAction::START_BOOTSTRAP_ENROLLMENT, PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT], false];
        yield 'nothing' => [[], false];
    }

    /**
     * A pending session binds its own person's factor only when its credential
     * allows an action that names an existing factor, and the guard's user
     * never stands in.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @param  bool  $binds
     * @return void
     */
    #[DataProvider('pendingActions')]
    public function testAPendingCredentialBindsPerItsActions(array $actions, bool $binds): void
    {
        $guarded = $this->signedInPerson();
        $pending = $this->person('pending@example.test');

        $own  = $this->totpFactor($pending);
        $held = $this->totpFactor($guarded);

        $this->pendingSession($pending, actions: $actions);

        $this->getJson('factors/' . $own->id)->assertStatus($binds ? 200 : 404);
        $this->getJson('factors/' . $held->id)->assertNotFound();
    }

    /**
     * A credential that does not validate is the resolver's to report: it is
     * never read as a miss.
     *
     * @return void
     */
    public function testAnInvalidPendingCredentialPropagates(): void
    {
        $factor = $this->totpFactor($this->signedInPerson());

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        self::assertInstanceOf(InvalidPendingCredentialException::class, $this->getJson('factors/' . $factor->id)->exception);
    }

    /**
     * The binding is an ownership rule, not permission to run the route: a
     * list-only credential binds on a verify URL, and the verification it runs
     * is refused.
     *
     * @return void
     */
    public function testAListOnlyCredentialBindsAndVerifyStillRefuses(): void
    {
        $pending = $this->person('pending@example.test');
        $factor  = $this->totpFactor($pending);

        $this->pendingSession($pending, actions: [PendingAction::LIST_FACTORS]);

        $this->postJson('factors/' . $factor->id . '/verify')->assertOk()->assertSee(FailureReason::NOT_FOUND->value);

        $this->pendingSession($pending);

        $this->postJson('factors/' . $factor->id . '/verify')->assertOk()->assertSee(FailureReason::INVALID_CODE->value);
    }

    /**
     * A scoped child binding is its parent's own lookup, which never reaches
     * the trait: the route must scope its parent to the caller itself.
     *
     * @return void
     */
    public function testAScopedChildBindingIsTheParentsOwnLookup(): void
    {
        $this->signedInPerson();

        $owner  = ScopedFactorOwner::query()->create(['email' => 'owner@example.test']);
        $theirs = $this->factorOf($this->person('other@example.test'), [
            'type'                 => 'totp',
            'authenticatable_type' => $owner->getMorphClass(),
            'authenticatable_id'   => (string) $owner->id,
        ]);

        $this->getJson('owners/' . $owner->id . '/factors/' . $theirs->id)->assertOk()->assertSee($theirs->id);
    }

    /**
     * A helper takes a factor's id: a bound model passed to one finds nothing,
     * and its identifier is what finds the factor.
     *
     * @return void
     */
    public function testABoundModelPassedToAHelperFindsNothing(): void
    {
        $factor = $this->totpFactor($this->signedInPerson());

        self::assertNull(Mfa::factor($factor));
        self::assertSame(FailureReason::NOT_FOUND, Mfa::removeFactor($factor)->reason);
        self::assertSame(FailureReason::NOT_FOUND, Mfa::sendCode($factor)->reason);
        self::assertSame(FailureReason::NOT_FOUND, Mfa::verify(Submission::factor($factor, AuthenticatorApp::code($factor)))->reason);
        self::assertSame($factor->id, Mfa::factor($factor->getFactorIdentifier())?->id);
    }
}
