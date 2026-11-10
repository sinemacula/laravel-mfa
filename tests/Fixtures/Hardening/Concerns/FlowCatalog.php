<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening\Concerns;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Hardening\ServerErrorAnswered;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FixedIdentityRequirement;

/**
 * Every flow that reads or changes the package's state, by name, with its
 * success and refusal branches where it has both. A flow seeds what it needs
 * and returns an action, which answers whether the branch its name promises was
 * reached: a healthy run must answer `true`, so a sweep over a catalogue that
 * stopped reaching its branch fails rather than proving nothing.
 *
 * It covers the flows that exist now; add to it with each new one, as a
 * catalogue does not cover a future method by itself.
 *
 * @phpstan-require-extends \Tests\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait FlowCatalog
{
    use ArrangesEnrollment;

    /** @var string The route carrying the gate. */
    private const string GATE_ROUTE = 'hardening/gate';

    /** @var string The route binding a factor. */
    private const string BINDING_ROUTE = 'hardening/factors';

    /** @var string A credential another person holds. */
    private const string FOREIGN_CREDENTIAL = 'Y3JlZGVudGlhbC10d28';

    /** @var list<string> Every plaintext value the flow seeded or was handed, to search failures for. */
    private array $flowSecrets = [];

    /**
     * The names of every flow, for a data provider.
     *
     * @return array<string, array{string}>
     */
    public static function flowNames(): array
    {
        $names = [
            'gate passes', 'gate refuses', 'factors', 'factor', 'factor missing', 'offered factors',
            'route binding', 'route binding foreign', 'recovery code status', 'authentication context',
            'is fresh', 'proofs', 'requirement', 'gateway send', 'gateway verify',
            'gateway verify wrong code', 'verify totp', 'verify totp wrong code', 'verify email',
            'verify email wrong code', 'verify recovery code', 'verify recovery code wrong',
            'verify passkey', 'verify passkey refused', 'verify pending session', 'send code',
            'send code missing', 'request assertion', 'request assertion missing', 'enrollment start',
            'enrollment start refused', 'enrollment confirm', 'enrollment confirm wrong code',
            'enrollment confirm bootstrap', 'enrollment resend', 'enrollment resend refused',
            'enrollment cancel', 'enrollment cancel refused', 'remove factor', 'remove last factor',
            'remove factor falling short', 'remove factor refused', 'rename factor', 'rename factor missing',
            'set preferred', 'set preferred missing', 'unlock factor', 'unlock factor not locked',
            'enable factor', 'enable factor not disabled', 'unlock identity', 'unlock identity not locked',
            'reset identity', 'forget identity',
            'generate recovery codes', 'generate recovery codes refused', 'prune', 'passkey registering',
            'passkey registering refused', 'passkey removing', 'passkey removing foreign',
            'challenge counters usable', 'challenge counters report passed', 'challenge counters report failed',
            'advance generation',
        ];

        return array_combine($names, array_map(static fn (string $name): array => [$name], $names));
    }

    /**
     * Each flow's seeding callable, by name.
     *
     * @return array<string, \Closure(): (\Closure(): bool)>
     */
    protected function flows(): array
    {
        return [...$this->readingFlows(), ...$this->verifyingFlows(), ...$this->enrollingFlows(), ...$this->lifecycleFlows(), ...$this->seamFlows()];
    }

    /**
     * Forget everything an earlier seed left in the application and the
     * package's tables, cheaply, so a flow can be seeded again without
     * rebuilding the application.
     *
     * @return void
     */
    protected function resetFlows(): void
    {
        $connection = DB::connection(StorageConnection::name());

        foreach (array_keys(TableNames::DEFAULTS) as $block) {
            $connection->table(TableNames::of($block))->delete();
        }

        TestUser::query()->delete();

        $this->container()->make(Session::class)->flush();

        Auth::forgetGuards();

        foreach ([IdentityRequirement::class, PasskeyGateway::class, PendingSessionResolver::class, Reauthenticator::class] as $seam) {
            $this->container()->forgetInstance($seam);
        }

        $this->mailbox = FakeEmailSender::fake($this->container());

        Carbon::setTestNow('2026-11-01 12:00:00');

        $this->reported    = [];
        $this->flowSecrets = [AuthenticatorApp::SECRET, self::ADDRESS, self::CREDENTIAL, self::FOREIGN_CREDENTIAL];

        $this->enableApplication();
    }

    /**
     * Define the routes the flows through the kernel call.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->get(self::GATE_ROUTE, static fn (): string => 'reached')->middleware('mfa:level=aal2');

        $router->get(self::BINDING_ROUTE . '/{factor}', static fn (Factor $factor): string => $factor->id)->middleware(SubstituteBindings::class);
    }

    /**
     * The flows that only read.
     *
     * @return array<string, \Closure(): (\Closure(): bool)>
     */
    private function readingFlows(): array
    {
        return [
            'gate passes'               => $this->gatePasses(...),
            'gate refuses'              => $this->gateRefuses(...),
            'factors'                   => $this->listingFactors(...),
            'factor'                    => $this->readingAFactor(...),
            'factor missing'            => $this->readingAMissingFactor(...),
            'offered factors'           => $this->offeringFactors(...),
            'route binding'             => $this->bindingARoute(...),
            'route binding foreign'     => $this->bindingAForeignRoute(...),
            'recovery code status'      => $this->readingRecoveryCodeStatus(...),
            'authentication context'    => $this->readingAuthenticationContext(...),
            'is fresh'                  => $this->askingIfFresh(...),
            'proofs'                    => $this->readingProofs(...),
            'requirement'               => $this->readingTheRequirement(...),
            'gateway send'              => $this->sendingThroughTheGateway(...),
            'gateway verify'            => $this->verifyingThroughTheGateway(...),
            'gateway verify wrong code' => $this->verifyingThroughTheGatewayWrongly(...),
        ];
    }

    /**
     * The flows that verify and send.
     *
     * @return array<string, \Closure(): (\Closure(): bool)>
     */
    private function verifyingFlows(): array
    {
        return [
            'verify totp'                => $this->verifyingTotp(...),
            'verify totp wrong code'     => $this->verifyingTotpWrongly(...),
            'verify email'               => $this->verifyingEmail(...),
            'verify email wrong code'    => $this->verifyingEmailWrongly(...),
            'verify recovery code'       => $this->verifyingARecoveryCode(...),
            'verify recovery code wrong' => $this->verifyingARecoveryCodeWrongly(...),
            'verify passkey'             => $this->verifyingAPasskey(...),
            'verify passkey refused'     => $this->verifyingARefusedPasskey(...),
            'verify pending session'     => $this->verifyingAPendingSession(...),
            'send code'                  => $this->sendingACode(...),
            'send code missing'          => $this->sendingACodeToNothing(...),
            'request assertion'          => $this->requestingAnAssertion(...),
            'request assertion missing'  => $this->requestingAnAssertionOfNothing(...),
        ];
    }

    /**
     * The flows that enrol.
     *
     * @return array<string, \Closure(): (\Closure(): bool)>
     */
    private function enrollingFlows(): array
    {
        return [
            'enrollment start'              => $this->startingAnEnrollment(...),
            'enrollment start refused'      => $this->startingARefusedEnrollment(...),
            'enrollment confirm'            => $this->confirmingAnEnrollment(...),
            'enrollment confirm wrong code' => $this->confirmingAnEnrollmentWrongly(...),
            'enrollment confirm bootstrap'  => $this->confirmingABootstrapEnrollment(...),
            'enrollment resend'             => $this->resendingAnEnrollmentCode(...),
            'enrollment resend refused'     => $this->resendingAnEnrollmentCodeTooSoon(...),
            'enrollment cancel'             => $this->cancelingAnEnrollment(...),
            'enrollment cancel refused'     => $this->cancelingNoEnrollment(...),
        ];
    }

    /**
     * The flows that change a factor or an identity afterwards.
     *
     * @return array<string, \Closure(): (\Closure(): bool)>
     */
    private function lifecycleFlows(): array
    {
        return [
            'remove factor'                   => $this->removingAFactor(...),
            'remove last factor'              => $this->removingTheLastFactor(...),
            'remove factor falling short'     => $this->removingAFactorFallingShort(...),
            'remove factor refused'           => $this->removingAFactorRefused(...),
            'rename factor'                   => $this->renamingAFactor(...),
            'rename factor missing'           => $this->renamingNothing(...),
            'set preferred'                   => $this->preferringAFactor(...),
            'set preferred missing'           => $this->preferringNothing(...),
            'unlock factor'                   => $this->unlockingAFactor(...),
            'unlock factor not locked'        => $this->unlockingAnUnlockedFactor(...),
            'enable factor'                   => $this->enablingAFactor(...),
            'enable factor not disabled'      => $this->enablingAnEnabledFactor(...),
            'unlock identity'                 => $this->unlockingAnIdentity(...),
            'unlock identity not locked'      => $this->unlockingAnUnlockedIdentity(...),
            'reset identity'                  => $this->resettingAnIdentity(...),
            'forget identity'                 => $this->forgettingAnIdentity(...),
            'generate recovery codes'         => $this->generatingRecoveryCodes(...),
            'generate recovery codes refused' => $this->generatingRecoveryCodesRefused(...),
            'prune'                           => $this->pruning(...),
        ];
    }

    /**
     * The flows another package or an application calls directly.
     *
     * @return array<string, \Closure(): (\Closure(): bool)>
     */
    private function seamFlows(): array
    {
        return [
            'passkey registering'              => $this->registeringAPasskey(...),
            'passkey registering refused'      => $this->registeringAnAssociatedPasskey(...),
            'passkey removing'                 => $this->removingAPasskey(...),
            'passkey removing foreign'         => $this->removingAForeignPasskey(...),
            'challenge counters usable'        => $this->askingTheCounters(...),
            'challenge counters report passed' => $this->reportingAPassedChallenge(...),
            'challenge counters report failed' => $this->reportingAFailedChallenge(...),
            'advance generation'               => $this->advancingTheGeneration(...),
        ];
    }

    /**
     * Note a plaintext value a failure must not hold, and return it.
     *
     * @param  string  $value
     * @return string
     */
    private function secret(#[\SensitiveParameter] string $value): string
    {
        $this->flowSecrets[] = $value;

        return $value;
    }

    /**
     * Whether a request through the kernel answered with the status, a server
     * error being thrown as the failure it stands for.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  int  $status
     * @return bool
     *
     * @throws \Tests\Fixtures\Hardening\ServerErrorAnswered
     */
    private function answered(TestResponse $response, int $status): bool
    {
        if ($response->status() >= 500) {
            throw new ServerErrorAnswered('The kernel answered with a server error.', 0, $response->exception);
        }

        return $response->status() === $status;
    }

    /**
     * Run the callback in a transaction on the storage connection, as a caller
     * of the gate or the counters does.
     *
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @throws \Throwable
     */
    private function inCallersTransaction(\Closure $callback): mixed
    {
        return DB::connection(StorageConnection::name())->transaction($callback);
    }

    /**
     * What a proof of the person's on the sign-in is bound to.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private function flowBinding(TestUser $user, Purpose $purpose = Purpose::STEP_UP, string $session = self::SESSION): ProofBinding
    {
        $owner = ProofOwner::of($user);

        return new ProofBinding($owner->type, $owner->key, self::APPLICATION, $session, $purpose);
    }

    /**
     * Someone other than the person flows act for.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function somebodyElse(): TestUser
    {
        return $this->person('somebody.else@example.test');
    }

    /**
     * A signed-in person with a confirmed TOTP factor, and a proof of it.
     *
     * @return array{\Tests\Fixtures\Identities\TestUser, \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function steppedUp(): array
    {
        $user = $this->steppedUpPerson();

        return [$user, Factor::query()->where('authenticatable_id', (string) $user->getKey())->where('type', 'totp')->sole()];
    }

    /**
     * A signed-in person with a confirmed TOTP factor and nothing proved.
     *
     * @return array{\Tests\Fixtures\Identities\TestUser, \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function holdingTotp(): array
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        return [$user, $this->totpFactor($user, ['application' => self::APPLICATION])];
    }

    /**
     * A signed-in person with a confirmed email factor and nothing proved.
     *
     * @return array{\Tests\Fixtures\Identities\TestUser, \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function holdingEmail(): array
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);

        return [$user, $this->emailFactor($user, attributes: ['application' => self::APPLICATION])];
    }

    /**
     * The gate lets a person through who proved enough.
     *
     * @return \Closure(): bool
     */
    private function gatePasses(): \Closure
    {
        $this->steppedUp();

        return fn (): bool => $this->answered($this->get(self::GATE_ROUTE), 200);
    }

    /**
     * The gate refuses a person who did not.
     *
     * @return \Closure(): bool
     */
    private function gateRefuses(): \Closure
    {
        $this->holdingTotp();

        return fn (): bool => $this->answered($this->get(self::GATE_ROUTE), 401);
    }

    /**
     * A person lists their factors.
     *
     * @return \Closure(): bool
     */
    private function listingFactors(): \Closure
    {
        $this->holdingTotp();

        return static fn (): bool => count(Mfa::factors(Callers::current())) === 1;
    }

    /**
     * A person reads one of their factors.
     *
     * @return \Closure(): bool
     */
    private function readingAFactor(): \Closure
    {
        [, $factor] = $this->holdingTotp();

        return static fn (): bool => Mfa::factor(Callers::current(), $factor->id) !== null;
    }

    /**
     * A person reads a factor that is not theirs.
     *
     * @return \Closure(): bool
     */
    private function readingAMissingFactor(): \Closure
    {
        $this->holdingTotp();

        return static fn (): bool => Mfa::factor(Callers::current(), 'missing') === null;
    }

    /**
     * A person is offered their factors.
     *
     * @return \Closure(): bool
     */
    private function offeringFactors(): \Closure
    {
        $this->holdingTotp();

        return static fn (): bool => count(Mfa::offeredFactors(Callers::current())) === 1;
    }

    /**
     * A route binds a factor of the person's.
     *
     * @return \Closure(): bool
     */
    private function bindingARoute(): \Closure
    {
        [, $factor] = $this->holdingTotp();

        return fn (): bool => $this->answered($this->get(self::BINDING_ROUTE . '/' . $factor->id), 200);
    }

    /**
     * A route misses a factor of someone else's.
     *
     * @return \Closure(): bool
     */
    private function bindingAForeignRoute(): \Closure
    {
        $this->holdingTotp();

        $theirs = $this->totpFactor($this->somebodyElse());

        return fn (): bool => $this->answered($this->get(self::BINDING_ROUTE . '/' . $theirs->id), 404);
    }

    /**
     * A person verifies a TOTP code.
     *
     * @return \Closure(): bool
     */
    private function verifyingTotp(): \Closure
    {
        [, $factor] = $this->holdingTotp();

        $submission = Submission::factor($factor->id, $this->secret(AuthenticatorApp::code($factor)));

        return static fn (): bool => Mfa::verify(Callers::current(), $submission)->isVerified();
    }

    /**
     * A person verifies the wrong TOTP code.
     *
     * @return \Closure(): bool
     */
    private function verifyingTotpWrongly(): \Closure
    {
        [, $factor] = $this->holdingTotp();

        $submission = Submission::factor($factor->id, $this->secret(AuthenticatorApp::code($factor, 5)));

        return static fn (): bool => !Mfa::verify(Callers::current(), $submission)->isVerified();
    }

    /**
     * A person verifies a code they were sent.
     *
     * @return \Closure(): bool
     */
    private function verifyingEmail(): \Closure
    {
        [, $factor] = $this->holdingEmail();

        [$challenge, $code] = $this->sentCode($factor);

        $submission = Submission::challenge($factor->id, $challenge, $this->secret($code));

        return static fn (): bool => Mfa::verify(Callers::current(), $submission)->isVerified();
    }

    /**
     * A person verifies the wrong code for a code they were sent.
     *
     * @return \Closure(): bool
     */
    private function verifyingEmailWrongly(): \Closure
    {
        [, $factor] = $this->holdingEmail();

        [$challenge, $code] = $this->sentCode($factor);

        $submission = Submission::challenge($factor->id, $challenge, $this->secret($code === '000000' ? '111111' : '000000'));

        return static fn (): bool => !Mfa::verify(Callers::current(), $submission)->isVerified();
    }

    /**
     * A person verifies a recovery code.
     *
     * @return \Closure(): bool
     */
    private function verifyingARecoveryCode(): \Closure
    {
        [$user] = $this->holdingTotp();

        $submission = Submission::recoveryCode($this->secret($this->recoveryCode($user)));

        return static fn (): bool => Mfa::verify(Callers::current(), $submission)->isVerified();
    }

    /**
     * A person verifies a recovery code they do not hold.
     *
     * @return \Closure(): bool
     */
    private function verifyingARecoveryCodeWrongly(): \Closure
    {
        [$user] = $this->holdingTotp();

        $this->recoveryCode($user);

        $submission = Submission::recoveryCode($this->secret('AAAAAAAAAAAA'));

        return static fn (): bool => !Mfa::verify(Callers::current(), $submission)->isVerified();
    }

    /**
     * A person verifies a passkey assertion.
     *
     * @return \Closure(): bool
     */
    private function verifyingAPasskey(): \Closure
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);
        $this->enablePasskeys();

        $submission = Submission::assertion($this->passkeyFactor($user)->id, ['id' => self::CREDENTIAL]);

        return static fn (): bool => Mfa::verify(Callers::current(), $submission)->isVerified();
    }

    /**
     * A passkey assertion that does not verify.
     *
     * @return \Closure(): bool
     */
    private function verifyingARefusedPasskey(): \Closure
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);
        $this->enablePasskeys(FailureReason::INVALID_CODE);

        $submission = Submission::assertion($this->passkeyFactor($user)->id, ['id' => self::CREDENTIAL]);

        return static fn (): bool => !Mfa::verify(Callers::current(), $submission)->isVerified();
    }

    /**
     * A person on a pending session verifies, which goes to the completion
     * seam.
     *
     * @return \Closure(): bool
     */
    private function verifyingAPendingSession(): \Closure
    {
        $user = $this->person();

        $this->beginSignIn($user, self::PENDING);
        $this->pendingSession($user, Requirement::none()->withAdditionalVerification());

        $factor     = $this->totpFactor($user);
        $submission = Submission::factor($factor->id, $this->secret(AuthenticatorApp::code($factor)));

        return static fn (): bool => Mfa::verify(Callers::current(), $submission)->isVerified();
    }

    /**
     * A person is sent a code.
     *
     * @return \Closure(): bool
     */
    private function sendingACode(): \Closure
    {
        [, $factor] = $this->holdingEmail();

        return static fn (): bool => Mfa::sendCode(Callers::current(), $factor->id)->wasSent();
    }

    /**
     * A person asks for a code for a factor they do not hold.
     *
     * @return \Closure(): bool
     */
    private function sendingACodeToNothing(): \Closure
    {
        $this->holdingEmail();

        return static fn (): bool => !Mfa::sendCode(Callers::current(), 'missing')->wasSent();
    }

    /**
     * A person asks for a passkey assertion.
     *
     * @return \Closure(): bool
     */
    private function requestingAnAssertion(): \Closure
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);
        $this->enablePasskeys();

        $factor = $this->passkeyFactor($user);

        return static fn (): bool => Mfa::requestAssertion(Callers::current(), $factor->id)->hasStarted();
    }

    /**
     * A person asks for an assertion of a factor they do not hold.
     *
     * @return \Closure(): bool
     */
    private function requestingAnAssertionOfNothing(): \Closure
    {
        $user = $this->signedInPerson();

        $this->recordFirstFactor($user);
        $this->enablePasskeys();

        return static fn (): bool => !Mfa::requestAssertion(Callers::current(), 'missing')->hasStarted();
    }

    /**
     * A person starts an enrolment.
     *
     * @return \Closure(): bool
     */
    private function startingAnEnrollment(): \Closure
    {
        $this->reauthenticatedPerson();

        return fn (): bool => Mfa::startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->hasStarted();
    }

    /**
     * A person who has not proved anything recently starts one.
     *
     * @return \Closure(): bool
     */
    private function startingARefusedEnrollment(): \Closure
    {
        $this->signedInPerson();

        return fn (): bool => !Mfa::startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT))->hasStarted();
    }

    /**
     * A person confirms their enrolment.
     *
     * @return \Closure(): bool
     */
    private function confirmingAnEnrollment(): \Closure
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $grant = $this->secret($this->grantOf($start));
        $code  = $this->secret($this->appCode($start));

        return fn (): bool => $this->mfa()->confirmEnrollment(Callers::current(), $grant, $code)->isConfirmed();
    }

    /**
     * A person confirms with the wrong code.
     *
     * @return \Closure(): bool
     */
    private function confirmingAnEnrollmentWrongly(): \Closure
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $grant = $this->secret($this->grantOf($start));
        $code  = $this->secret($this->wrongCode($start));

        return fn (): bool => !$this->mfa()->confirmEnrollment(Callers::current(), $grant, $code)->isConfirmed();
    }

    /**
     * A person on a bootstrap session confirms, which goes to the completion
     * seam.
     *
     * @return \Closure(): bool
     */
    private function confirmingABootstrapEnrollment(): \Closure
    {
        $this->bootstrapPerson(Requirement::none()->withAdditionalVerification());

        $start = $this->startedTotp();
        $grant = $this->secret($this->grantOf($start));
        $code  = $this->secret($this->appCode($start));

        return fn (): bool => $this->mfa()->confirmEnrollment(Callers::current(), $grant, $code)->isConfirmed();
    }

    /**
     * A person is sent their enrolment's code again.
     *
     * @return \Closure(): bool
     */
    private function resendingAnEnrollmentCode(): \Closure
    {
        $this->reauthenticatedPerson();

        $grant = $this->secret($this->grantOf($this->startedEmail()));

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));

        return fn (): bool => $this->mfa()->resendEnrollmentCode(Callers::current(), $grant)->wasSent();
    }

    /**
     * A person asks for it again too soon.
     *
     * @return \Closure(): bool
     */
    private function resendingAnEnrollmentCodeTooSoon(): \Closure
    {
        $this->reauthenticatedPerson();

        $grant = $this->secret($this->grantOf($this->startedEmail()));

        return fn (): bool => !$this->mfa()->resendEnrollmentCode(Callers::current(), $grant)->wasSent();
    }

    /**
     * A person cancels their enrolment.
     *
     * @return \Closure(): bool
     */
    private function cancelingAnEnrollment(): \Closure
    {
        $this->reauthenticatedPerson();

        $grant = $this->secret($this->grantOf($this->startedTotp()));

        return fn (): bool => $this->mfa()->cancelEnrollment(Callers::current(), $grant);
    }

    /**
     * A person cancels an enrolment that does not exist.
     *
     * @return \Closure(): bool
     */
    private function cancelingNoEnrollment(): \Closure
    {
        $this->reauthenticatedPerson();

        return fn (): bool => !$this->mfa()->cancelEnrollment(Callers::current(), 'no-such-grant');
    }

    /**
     * A person removes one of two factors.
     *
     * @return \Closure(): bool
     */
    private function removingAFactor(): \Closure
    {
        [$user] = $this->steppedUp();

        $email = $this->emailFactor($user, attributes: ['application' => self::APPLICATION]);

        return static fn (): bool => Mfa::removeFactor(Callers::current(), $email->id)->wasMade();
    }

    /**
     * A person removes their last factor, which takes the recovery codes.
     *
     * @return \Closure(): bool
     */
    private function removingTheLastFactor(): \Closure
    {
        [$user, $factor] = $this->steppedUp();

        $this->secret($this->recoveryCode($user));

        return static fn (): bool => Mfa::removeFactor(Callers::current(), $factor->id)->wasMade();
    }

    /**
     * A removal leaves the session short of its requirement, which goes to the
     * session transition.
     *
     * @return \Closure(): bool
     */
    private function removingAFactorFallingShort(): \Closure
    {
        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement(Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2)));

        [, $totp] = $this->holdingTotp();

        $user  = TestUser::query()->sole();
        $email = $this->emailFactor($user, attributes: ['application' => self::APPLICATION]);

        Mfa::verify(Callers::current(), Submission::factor($totp->id, AuthenticatorApp::code($totp)));

        [$challenge, $code] = $this->sentCode($email);

        Mfa::verify(Callers::current(), Submission::challenge($email->id, $challenge, $code));

        return static fn (): bool => Mfa::removeFactor(Callers::current(), $totp->id)->outstanding !== null;
    }

    /**
     * A person who has not stepped up removes a factor.
     *
     * @return \Closure(): bool
     */
    private function removingAFactorRefused(): \Closure
    {
        [, $factor] = $this->holdingTotp();

        return static fn (): bool => !Mfa::removeFactor(Callers::current(), $factor->id)->wasMade();
    }

    /**
     * A person renames a factor.
     *
     * @return \Closure(): bool
     */
    private function renamingAFactor(): \Closure
    {
        [, $factor] = $this->holdingTotp();

        return static fn (): bool => Mfa::renameFactor(Callers::current(), $factor->id, 'Phone')->wasMade();
    }

    /**
     * A person renames a factor they do not hold.
     *
     * @return \Closure(): bool
     */
    private function renamingNothing(): \Closure
    {
        $this->holdingTotp();

        return static fn (): bool => !Mfa::renameFactor(Callers::current(), 'missing', 'Phone')->wasMade();
    }

    /**
     * A person prefers a factor.
     *
     * @return \Closure(): bool
     */
    private function preferringAFactor(): \Closure
    {
        [, $factor] = $this->holdingTotp();

        return static fn (): bool => Mfa::setPreferredFactor(Callers::current(), $factor->id)->wasMade();
    }

    /**
     * A person prefers a factor they do not hold.
     *
     * @return \Closure(): bool
     */
    private function preferringNothing(): \Closure
    {
        $this->holdingTotp();

        return static fn (): bool => !Mfa::setPreferredFactor(Callers::current(), 'missing')->wasMade();
    }

    /**
     * An administrator lifts a factor's lockout.
     *
     * @return \Closure(): bool
     */
    private function unlockingAFactor(): \Closure
    {
        [$user, $factor] = $this->holdingTotp();

        $factor->update(['locked_until' => CarbonImmutable::now()->addHour()]);

        return static fn (): bool => Mfa::unlockFactor($user, $factor->id, new Actor('admin', '9'));
    }

    /**
     * An administrator lifts a lockout that is not there.
     *
     * @return \Closure(): bool
     */
    private function unlockingAnUnlockedFactor(): \Closure
    {
        [$user, $factor] = $this->holdingTotp();

        return static fn (): bool => !Mfa::unlockFactor($user, $factor->id, new Actor('admin', '9'));
    }

    /**
     * An administrator enables a factor the failure ceiling disabled.
     *
     * @return \Closure(): bool
     */
    private function enablingAFactor(): \Closure
    {
        [$user, $factor] = $this->holdingTotp();

        $factor->update(['disabled_at' => CarbonImmutable::now()]);

        return static fn (): bool => Mfa::enableFactor($user, $factor->id, new Actor('admin', '9'));
    }

    /**
     * An administrator enables a factor that is not disabled.
     *
     * @return \Closure(): bool
     */
    private function enablingAnEnabledFactor(): \Closure
    {
        [$user, $factor] = $this->holdingTotp();

        return static fn (): bool => !Mfa::enableFactor($user, $factor->id, new Actor('admin', '9'));
    }

    /**
     * An administrator lifts an identity's lockout.
     *
     * @return \Closure(): bool
     */
    private function unlockingAnIdentity(): \Closure
    {
        [$user] = $this->holdingTotp();

        $owner = ProofOwner::of($user);

        IdentityState::query()->updateOrCreate(
            ['authenticatable_type' => $owner->type, 'authenticatable_id' => $owner->key],
            ['locked_until' => CarbonImmutable::now()->addHour()],
        );

        return static fn (): bool => Mfa::unlockIdentity($user, new Actor('admin', '9'));
    }

    /**
     * An administrator lifts an identity's lockout that is not there.
     *
     * @return \Closure(): bool
     */
    private function unlockingAnUnlockedIdentity(): \Closure
    {
        [$user] = $this->holdingTotp();

        return static fn (): bool => !Mfa::unlockIdentity($user, new Actor('admin', '9'));
    }

    /**
     * An administrator resets an identity.
     *
     * @return \Closure(): bool
     */
    private function resettingAnIdentity(): \Closure
    {
        [$user] = $this->holdingTotp();

        $this->recoveryCode($user);

        return static function () use ($user): bool {

            Mfa::resetIdentity($user, new Actor('admin', '9'), 'Lost their phone.');

            return WriteConnection::query(Factor::query())->count() === 0;
        };
    }

    /**
     * An application forgets an identity.
     *
     * @return \Closure(): bool
     */
    private function forgettingAnIdentity(): \Closure
    {
        [$user] = $this->holdingTotp();

        $this->recoveryCode($user);

        return static function () use ($user): bool {

            Mfa::forgetIdentity($user);

            return WriteConnection::query(Factor::query())->count() === 0;
        };
    }

    /**
     * A person generates their recovery codes.
     *
     * @return \Closure(): bool
     */
    private function generatingRecoveryCodes(): \Closure
    {
        $this->steppedUp();

        return static fn (): bool => Mfa::generateRecoveryCodes(Callers::current())->wasGenerated();
    }

    /**
     * A person who has not stepped up generates them.
     *
     * @return \Closure(): bool
     */
    private function generatingRecoveryCodesRefused(): \Closure
    {
        $this->holdingTotp();

        return static fn (): bool => !Mfa::generateRecoveryCodes(Callers::current())->wasGenerated();
    }

    /**
     * A person reads how many recovery codes they have left.
     *
     * @return \Closure(): bool
     */
    private function readingRecoveryCodeStatus(): \Closure
    {
        [$user] = $this->holdingTotp();

        $this->recoveryCode($user);

        return static fn (): bool => Mfa::recoveryCodeStatus(Callers::current()) !== null;
    }

    /**
     * An application reads what the session has proved.
     *
     * @return \Closure(): bool
     */
    private function readingAuthenticationContext(): \Closure
    {
        $this->steppedUp();

        return static fn (): bool => Mfa::authenticationContext(Callers::current())['accepted'];
    }

    /**
     * An application asks if the session is fresh for an operation.
     *
     * @return \Closure(): bool
     */
    private function askingIfFresh(): \Closure
    {
        $this->steppedUp();

        return static fn (): bool => Mfa::isFresh(Callers::current(), 'mfa.add_factor');
    }

    /**
     * A scheduled job prunes what expired.
     *
     * @return \Closure(): bool
     */
    private function pruning(): \Closure
    {
        [, $factor] = $this->holdingTotp();

        $this->reauthenticatedPerson();
        $this->startedTotp();

        Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor, 5)));

        Carbon::setTestNow(CarbonImmutable::now()->addDays(60));

        return static function (): bool {

            $pruned = Mfa::prune();

            return $pruned->enrollments > 0 && $pruned->attempts > 0;
        };
    }

    /**
     * An application reads the session's proofs.
     *
     * @return \Closure(): bool
     */
    private function readingProofs(): \Closure
    {
        $this->steppedUp();

        return static fn (): bool => count(Mfa::proofs(Callers::current())) > 0;
    }

    /**
     * An application reads the session's requirement.
     *
     * @return \Closure(): bool
     */
    private function readingTheRequirement(): \Closure
    {
        $this->holdingTotp();

        $this->enableApplication(['requirement' => 'always']);

        return static fn (): bool => !Mfa::requirement(Callers::current())->isEmpty();
    }

    /**
     * A passkey is registered as a factor.
     *
     * @return \Closure(): bool
     */
    private function registeringAPasskey(): \Closure
    {
        $user = $this->reauthenticatedPerson();

        $this->enablePasskeys();

        $registration = new PasskeyRegistration(self::CREDENTIAL, new ObservedProperties(userPresence: true), $this->flowBinding($user, Purpose::ENROLLMENT));
        $gate         = $this->container()->make(PasskeyChangeGate::class);

        return fn (): bool => $this->inCallersTransaction(static fn (): bool => $gate->registering(Callers::of($user, self::APPLICATION), $registration) !== null);
    }

    /**
     * A credential associated already is registered.
     *
     * @return \Closure(): bool
     */
    private function registeringAnAssociatedPasskey(): \Closure
    {
        $user = $this->reauthenticatedPerson();

        $this->enablePasskeys();
        $this->passkeyFactor($this->somebodyElse());

        $registration = new PasskeyRegistration(self::CREDENTIAL, new ObservedProperties(userPresence: true), $this->flowBinding($user, Purpose::ENROLLMENT));
        $gate         = $this->container()->make(PasskeyChangeGate::class);

        return fn (): bool => $this->refusedWith(
            FailureReason::CREDENTIAL_ASSOCIATED,
            fn (): mixed => $this->inCallersTransaction(static fn (): mixed => $gate->registering(Callers::of($user, self::APPLICATION), $registration)),
        );
    }

    /**
     * A person removes a passkey they hold, having stepped up with another
     * factor.
     *
     * @return \Closure(): bool
     */
    private function removingAPasskey(): \Closure
    {
        [$user] = $this->steppedUp();

        $this->enablePasskeys();
        $this->passkeyFactor($user);

        Factor::query()->where('type', 'passkey')->update(['application' => self::APPLICATION]);

        $gate = $this->container()->make(PasskeyChangeGate::class);

        return fn (): bool => $this->inCallersTransaction(static function () use ($gate, $user): bool {

            $gate->removing(Callers::of($user, self::APPLICATION), self::CREDENTIAL);

            return WriteConnection::query(Factor::query())->where('type', 'passkey')->count() === 0;
        });
    }

    /**
     * A person removes a credential someone else holds.
     *
     * @return \Closure(): bool
     */
    private function removingAForeignPasskey(): \Closure
    {
        [$user] = $this->steppedUp();

        $this->enablePasskeys();
        $this->passkeyFactor($this->somebodyElse(), self::FOREIGN_CREDENTIAL);

        $gate = $this->container()->make(PasskeyChangeGate::class);

        return fn (): bool => $this->refusedWith(FailureReason::NOT_FOUND, fn (): mixed => $this->inCallersTransaction(static function () use ($gate, $user): void {
            $gate->removing(Callers::of($user, self::APPLICATION), self::FOREIGN_CREDENTIAL);
        }));
    }

    /**
     * Whether the call was refused for the reason.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  \Closure(): mixed  $call
     * @return bool
     */
    private function refusedWith(FailureReason $reason, \Closure $call): bool
    {
        try {
            $call();
        } catch (OperationRefusedException $refusal) {
            return $refusal->reason === $reason;
        }

        return false;
    }

    /**
     * Another package asks if a factor may be challenged.
     *
     * @return \Closure(): bool
     */
    private function askingTheCounters(): \Closure
    {
        [$user, $factor] = $this->holdingEmail();

        $counters = $this->container()->make(ChallengeCounters::class);
        $binding  = $this->flowBinding($user);

        $caller = CallerContext::forIdentity($user, $binding->application);

        return fn (): bool => $this->inCallersTransaction(static fn (): bool => $counters->isUsable($caller, $factor, $binding)->isAdmitted());
    }

    /**
     * Another package reports a challenge that passed.
     *
     * @return \Closure(): bool
     */
    private function reportingAPassedChallenge(): \Closure
    {
        [$user, $factor] = $this->holdingEmail();

        $counters = $this->container()->make(ChallengeCounters::class);
        $binding  = $this->flowBinding($user);

        $caller = CallerContext::forIdentity($user, $binding->application);

        return fn (): bool => $this->inCallersTransaction(static fn (): bool => $counters->report($caller, $factor, $binding, true)->passed);
    }

    /**
     * Another package reports a challenge that failed.
     *
     * @return \Closure(): bool
     */
    private function reportingAFailedChallenge(): \Closure
    {
        [$user, $factor] = $this->holdingEmail();

        $counters = $this->container()->make(ChallengeCounters::class);
        $binding  = $this->flowBinding($user);

        $caller = CallerContext::forIdentity($user, $binding->application);

        return fn (): bool => $this->inCallersTransaction(static fn (): bool => $counters->report($caller, $factor, $binding, false)->isFailed());
    }

    /**
     * The gateway sends a code.
     *
     * @return \Closure(): bool
     */
    private function sendingThroughTheGateway(): \Closure
    {
        [$user, $factor] = $this->holdingEmail();

        $gateway = $this->container()->make(ChallengeGateway::class);
        $binding = $this->flowBinding($user);

        return static fn (): bool => $gateway->send(Callers::current(), $factor, $binding)->wasSent();
    }

    /**
     * The gateway verifies a code it sent.
     *
     * @return \Closure(): bool
     */
    private function verifyingThroughTheGateway(): \Closure
    {
        [$user, $factor] = $this->holdingEmail();

        [$challenge, $code] = $this->sentCode($factor);

        $gateway = $this->container()->make(ChallengeGateway::class);
        $binding = $this->flowBinding($user);

        $this->secret($code);

        return static fn (): bool => $gateway->verify(Callers::current(), $factor, $binding, $challenge, $code)->hasPassed();
    }

    /**
     * The gateway refuses the wrong code.
     *
     * @return \Closure(): bool
     */
    private function verifyingThroughTheGatewayWrongly(): \Closure
    {
        [$user, $factor] = $this->holdingEmail();

        [$challenge, $code] = $this->sentCode($factor);

        $gateway = $this->container()->make(ChallengeGateway::class);
        $binding = $this->flowBinding($user);
        $wrong   = $this->secret($code === '000000' ? '111111' : '000000');

        return static fn (): bool => !$gateway->verify(Callers::current(), $factor, $binding, $challenge, $wrong)->hasPassed();
    }

    /**
     * An application advances an identity's verification generation.
     *
     * @return \Closure(): bool
     */
    private function advancingTheGeneration(): \Closure
    {
        [$user] = $this->holdingTotp();

        return static fn (): bool => VerificationGeneration::advance($user) === 1;
    }
}
