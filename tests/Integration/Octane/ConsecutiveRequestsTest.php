<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use Illuminate\Support\Testing\Fakes\EventFake;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\BeginSignInOnLogin;
use SineMacula\Laravel\Mfa\Proofs\ForgetSignInOnLogout;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Exceptions\CommitFailedException;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FixedIdentityRequirement;
use Tests\Integration\Octane\Concerns\ServesRequestsThroughOctane;
use Tests\Integration\Octane\Fixtures\ConfigurationReadingProofStore;
use Tests\TestCase;

/**
 * One Octane worker serves different people with the package's services
 * resolved at boot, as `octane.warm` would; nothing leaks between them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
#[CoversClass(FactorService::class)]
#[CoversClass(LifecycleService::class)]
#[CoversClass(ProofService::class)]
#[CoversClass(VerificationService::class)]
#[CoversClass(EnsureMfaRequirementIsMet::class)]
#[CoversClass(BeginSignInOnLogin::class)]
#[CoversClass(ForgetSignInOnLogout::class)]
#[CoversClass(WriteConnection::class)]
final class ConsecutiveRequestsTest extends TestCase
{
    use ServesRequestsThroughOctane;

    /** @var string The header naming the person a request acts for. */
    private const string PERSON = 'X-Person';

    /** @var string The application, which is the guard's name. */
    private const string APPLICATION = 'web';

    /** @var string The address the email factor delivers to. */
    private const string ADDRESS = 'alice@example.test';

    /** @var string Config key a request sets for itself. */
    private const string MARKER = 'mfa-test.marker';

    /** @var string The directory the sessions are kept in. */
    private string $sessions = '';

    /** @var list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent> What the booted dispatcher reported. */
    private array $reported = [];

    /** @var bool Whether the next commit on the storage connection fails. */
    private bool $failNextCommit = false;

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-11-01 12:00:00');

        $app = $this->octaneApplication();

        Auth::viaRequest('person-header', static fn (Request $request): ?TestUser => TestUser::query()->find($request->header(self::PERSON)));

        Event::listen(MfaEvent::class, function (MfaEvent $event): void {
            $this->reported[] = $event;
        });

        Event::listen(TransactionCommitting::class, function (TransactionCommitting $event): void {

            if (!$this->failNextCommit || $event->connectionName !== StorageConnection::resolvedName()) {
                return;
            }

            $this->failNextCommit = false;

            throw new CommitFailedException('The database refused the commit.');
        });

        $warmed = [
            'mfa',
            EventDispatcher::class,
            ProofService::class,
            FactorService::class,
            VerificationService::class,
            LifecycleService::class,
            RequirementService::class,
            SessionRevoker::class,
        ];

        foreach ($warmed as $service) {
            $app->make($service);
        }

        $this->bootOctaneWorker();
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();

        foreach (glob($this->sessions . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            unlink($file);
        }

        if ($this->sessions === '' || !is_dir($this->sessions)) {
            return;
        }

        rmdir($this->sessions);
    }

    /**
     * @return void
     */
    public function testConsecutiveRequestsForDifferentPeopleShareNothing(): void
    {
        $alice = $this->person(self::ADDRESS);
        $bob   = $this->person('bob@example.test');
        $totp  = $this->factorOf($alice, AuthenticatorApp::FACTOR);
        $email = $this->factorOf($alice, ['type' => 'email', 'destination' => self::ADDRESS]);

        $this->serve($this->request('POST', '/sign-in', $alice))->assertOk();
        $this->serve($this->request('POST', '/sign-in', $bob))->assertOk();

        $this->assertRefusedAtTheGate($alice);

        $this->assertVerifies($alice, $totp);

        $this->serve($this->request('GET', '/gate', $alice))->assertOk();

        self::assertSame([], $this->factorsOf($bob));
        self::assertSame([], $this->proofsOf($bob));

        $this->assertRefusedAtTheGate($bob);

        $this->serve($this->verification($bob, $totp))->assertOk()->assertJson(['verified' => false]);

        self::assertEqualsCanonicalizing([$totp->id, $email->id], $this->factorsOf($alice));

        $challenge = $this->serve($this->request('POST', '/send-code', $alice, ['factor' => $email->id]))->assertOk()->json('challenge');

        self::assertIsString($challenge);

        $mailbox = $this->container()->make(EmailSender::class);

        self::assertInstanceOf(FakeEmailSender::class, $mailbox);

        $code = $mailbox->lastCodeTo(self::ADDRESS);

        self::assertNotNull($code);

        $submitted = ['factor' => $email->id, 'challenge' => $challenge, 'code' => $code];

        $this->serve($this->request('POST', '/verify-code', $alice, $submitted))->assertOk()->assertJson(['verified' => true]);

        self::assertSame(['totp', 'email'], $this->proofsOf($alice));

        $this->serve($this->request('POST', '/remove', $alice, ['factor' => $totp->id]))->assertOk()->assertJson(['made' => true]);

        self::assertSame([$email->id], $this->factorsOf($alice));
        self::assertSame(['email'], $this->proofsOf($alice));

        $this->assertRefusedAtTheGate($alice);

        self::assertSame([], $this->factorsOf($bob));
        self::assertSame([], $this->proofsOf($bob));

        $this->assertRefusedAtTheGate($bob);

        self::assertSame([$email->id], $this->factorsOf($alice));
        self::assertSame(['email'], $this->proofsOf($alice));
    }

    /**
     * The listeners are registered once, on the booted application.
     *
     * @return void
     */
    public function testEachSignInEventReachesWhatTheRequestBound(): void
    {
        $alice = $this->person(self::ADDRESS);

        self::assertSame(['begin:first'], $this->serve($this->request('POST', '/events/login', $alice, ['marker' => 'first']))->assertOk()->json('calls'));
        self::assertSame(['forget:second'], $this->serve($this->request('POST', '/events/logout', $alice, ['marker' => 'second']))->assertOk()->json('calls'));
        self::assertSame(['forget:third'], $this->serve($this->request('POST', '/events/current-device-logout', $alice, ['marker' => 'third']))->assertOk()->json('calls'));
    }

    /**
     * @return void
     */
    public function testConfigurationAndSeamsOfOneRequestStayInIt(): void
    {
        $alice = $this->person(self::ADDRESS);

        $this->serve($this->request('GET', '/settled', $alice))->assertOk()->assertJson(['digits' => 8, 'requirement' => ['additional_verification']]);
        $this->serve($this->request('GET', '/unsettled', $alice))->assertOk()->assertJson(['digits' => 6, 'requirement' => []]);
    }

    /**
     * The booted dispatcher misses that report and gets the next request's.
     *
     * @return void
     */
    public function testADispatcherOneRequestBindsReceivesItsReports(): void
    {
        $alice = $this->person(self::ADDRESS);
        $totp  = $this->factorOf($alice, AuthenticatorApp::FACTOR);

        $this->serve($this->request('POST', '/sign-in', $alice))->assertOk();

        $submitted = ['factor' => $totp->id, 'code' => AuthenticatorApp::code($totp)];

        $this->serve($this->request('POST', '/verify-with-own-dispatcher', $alice, $submitted))->assertOk()->assertJson(['reports' => 1]);

        $this->assertPassedReports(0);

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(60));

        $this->assertVerifies($alice, $totp);
        $this->assertPassedReports(1);
    }

    /**
     * @return void
     */
    public function testAPinThatThrowsIsReleasedForTheNextRequest(): void
    {
        $alice = $this->person(self::ADDRESS);

        $this->serve($this->request('GET', '/pin-that-throws', $alice))->assertStatus(500);

        self::assertFalse(self::readsOnWriteConnection(DB::connection(StorageConnection::name())));

        $this->serve($this->request('GET', '/pin-state', $alice))->assertOk()->assertJson(['pinned' => false]);
    }

    /**
     * The retry is the only report and the only proof.
     *
     * @return void
     */
    public function testAFailedCommitLeavesNothingWaitingForTheNextRequest(): void
    {
        $alice = $this->person(self::ADDRESS);
        $totp  = $this->factorOf($alice, AuthenticatorApp::FACTOR);

        $this->serve($this->request('POST', '/sign-in', $alice))->assertOk();

        $this->failNextCommit = true;

        $this->serve($this->verification($alice, $totp))->assertStatus(500);

        self::assertFalse(DB::connection(StorageConnection::name())->getPdo()->inTransaction());

        $this->assertPassedReports(0);

        self::assertSame([], $this->proofsOf($alice));

        $this->assertVerifies($alice, $totp);
        $this->assertPassedReports(1);

        self::assertSame(['totp'], $this->proofsOf($alice));
    }

    /**
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->group(['middleware' => StartSession::class], function () use ($router): void {

            $router->post('sign-in', static function (Request $request): JsonResponse {

                self::dispatcher()->dispatch(new Login(self::APPLICATION, self::user(), false));

                return new JsonResponse;
            });

            $router->get('gate', static fn (): string => 'reached')->middleware('mfa:level=aal2');

            $router->get('factors', self::factorIds(...));

            $router->get('proofs', self::proofMethods(...));

            $router->post('verify', static fn (Request $request): JsonResponse => self::verified($request));

            $router->post('send-code', self::sent(...));

            $router->post('verify-code', static function (Request $request): JsonResponse {

                $submission = Submission::challenge($request->string('factor')->toString(), $request->string('challenge')->toString(), $request->string('code')->toString());

                return new JsonResponse(['verified' => Mfa::verify(Callers::current(), $submission)->isVerified()]);
            });

            $router->post('remove', self::removed(...));

            $router->post('verify-with-own-dispatcher', static function (Request $request): JsonResponse {

                $fake = new EventFake(self::dispatcher(), [VerificationPassed::class]);

                app()->instance('events', $fake);

                $verified = self::verified($request);

                return new JsonResponse(['verified' => $verified->getData(true), 'reports' => count($fake->dispatched(VerificationPassed::class))]);
            });

            $router->post('events/login', self::firingLogin(...));

            $router->post('events/logout', self::firingLogout(...));

            $router->post('events/current-device-logout', self::firingCurrentDeviceLogout(...));

            $router->get('settled', static function (): JsonResponse {

                config()->set('mfa.totp.digits', 8);

                app()->instance(IdentityRequirement::class, new FixedIdentityRequirement(Requirement::none()->withAdditionalVerification()));

                return self::settings();
            });

            $router->get('unsettled', static fn (): JsonResponse => self::settings());

            $router->get('pin-that-throws', static fn (): never => WriteConnection::during(new Factor, static fn (): never => throw new \RuntimeException('The lookup failed.')));

            $router->get('pin-state', self::pinState(...));
        });
    }

    /**
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $this->sessions = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mfa-octane-' . Str::lower((string) Str::ulid());

        mkdir($this->sessions);

        FakeEmailSender::fake($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('app.debug', false);
        $config->set('logging.default', 'null');
        $config->set('auth.defaults.guard', self::APPLICATION);
        $config->set('auth.providers.users', ['driver' => 'eloquent', 'model' => TestUser::class]);
        $config->set('auth.guards.' . self::APPLICATION, ['driver' => 'person-header', 'provider' => 'users']);
        $config->set('session.driver', 'file');
        $config->set('session.files', $this->sessions);
        $config->set('mfa.applications.' . self::APPLICATION, [
            'types'        => ['totp', 'email'],
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]);
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    private static function factorIds(): JsonResponse
    {
        return new JsonResponse(['ids' => array_map(static fn (FactorSummary $factor): string => $factor->id, Mfa::factors(Callers::current()))]);
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    private static function proofMethods(): JsonResponse
    {
        return new JsonResponse(['methods' => array_map(static fn (Proof $proof): string => $proof->method, Mfa::proofs(Callers::current()))]);
    }

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    private static function sent(Request $request): JsonResponse
    {
        return new JsonResponse(['challenge' => Mfa::sendCode(Callers::current(), $request->string('factor')->toString())->challengeId]);
    }

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    private static function removed(Request $request): JsonResponse
    {
        return new JsonResponse(['made' => Mfa::removeFactor(Callers::current(), $request->string('factor')->toString())->wasMade()]);
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    private static function pinState(): JsonResponse
    {
        return new JsonResponse(['pinned' => self::readsOnWriteConnection(DB::connection(StorageConnection::name()))]);
    }

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    private static function firingLogin(Request $request): JsonResponse
    {
        return self::firingInOwnSandbox($request, static fn (TestUser $user): object => new Login(self::APPLICATION, $user, false));
    }

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    private static function firingLogout(Request $request): JsonResponse
    {
        return self::firingInOwnSandbox($request, static fn (TestUser $user): object => new Logout(self::APPLICATION, $user));
    }

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    private static function firingCurrentDeviceLogout(Request $request): JsonResponse
    {
        return self::firingInOwnSandbox($request, static fn (TestUser $user): object => new CurrentDeviceLogout(self::APPLICATION, $user));
    }

    /**
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private static function user(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->findOrFail(Auth::guard(self::APPLICATION)->id());
    }

    /**
     * @return \Illuminate\Contracts\Events\Dispatcher
     */
    private static function dispatcher(): Dispatcher
    {
        return app(Dispatcher::class);
    }

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    private static function verified(Request $request): JsonResponse
    {
        $submission = Submission::factor($request->string('factor')->toString(), $request->string('code')->toString());

        return new JsonResponse(['verified' => Mfa::verify(Callers::current(), $submission)->isVerified()]);
    }

    /**
     * Binds a proof store built from this sandbox's config; answers its calls.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Tests\Fixtures\Identities\TestUser): object  $event
     * @return \Illuminate\Http\JsonResponse
     */
    private static function firingInOwnSandbox(Request $request, \Closure $event): JsonResponse
    {
        config()->set(self::MARKER, $request->string('marker')->toString());

        $calls = [];

        app()->bind(ProofStore::class, static function (Application $app) use (&$calls): ConfigurationReadingProofStore {

            /** @var \Illuminate\Config\Repository $config */
            $config = $app->make('config');

            $calls[] = $store = new ConfigurationReadingProofStore($config->string(self::MARKER));

            return $store;
        });

        self::dispatcher()->dispatch($event(self::user()));

        return new JsonResponse(['calls' => array_merge(...array_map(static fn (ConfigurationReadingProofStore $store): array => $store->calls, $calls))]);
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    private static function settings(): JsonResponse
    {
        $driver = Mfa::driver('totp');

        self::assertInstanceOf(TotpDriver::class, $driver);

        return new JsonResponse(['digits' => $driver->parameters()->digits, 'requirement' => array_keys(Mfa::requirement(Callers::current())->toArray())]);
    }

    /**
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    private static function readsOnWriteConnection(Connection $connection): bool
    {
        return (fn (): bool => $this->readOnWriteConnection)->call($connection);
    }

    /**
     * Carries the person's session cookie.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  \Tests\Fixtures\Identities\TestUser  $person
     * @param  array<string, mixed>  $parameters
     * @return \Illuminate\Http\Request
     */
    private function request(string $method, string $uri, TestUser $person, array $parameters = []): Request
    {
        $cookie = config()->string('session.cookie');

        return Request::create($uri, $method, $parameters, [$cookie => str_pad((string) $person->id, 40, 'a')], server: [
            'HTTP_' . str_replace('-', '_', strtoupper(self::PERSON)) => (string) $person->id,
            'HTTP_ACCEPT'                                             => 'application/json',
            'REMOTE_ADDR'                                             => '203.0.113.7',
        ]);
    }

    /**
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function person(string $email): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->create(['email' => $email]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $person
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factorOf(TestUser $person, array $attributes): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $person->getMorphClass(),
            'authenticatable_id'   => (string) $person->id,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            'application'          => self::APPLICATION,
            ...$attributes,
        ]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $person
     * @return list<string>
     */
    private function factorsOf(TestUser $person): array
    {
        /** @var list<string> */
        return $this->serve($this->request('GET', '/factors', $person))->assertOk()->json('ids');
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $person
     * @return list<string>
     */
    private function proofsOf(TestUser $person): array
    {
        /** @var list<string> */
        return $this->serve($this->request('GET', '/proofs', $person))->assertOk()->json('methods');
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $person
     * @return void
     */
    private function assertRefusedAtTheGate(TestUser $person): void
    {
        $this->serve($this->request('GET', '/gate', $person))->assertStatus(401);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $person
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return \Illuminate\Http\Request
     */
    private function verification(TestUser $person, Factor $factor): Request
    {
        return $this->request('POST', '/verify', $person, ['factor' => $factor->id, 'code' => AuthenticatorApp::code($factor)]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $person
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return void
     */
    private function assertVerifies(TestUser $person, Factor $factor): void
    {
        $this->serve($this->verification($person, $factor))->assertOk()->assertJson(['verified' => true]);
    }

    /**
     * @param  int  $count
     * @return void
     */
    private function assertPassedReports(int $count): void
    {
        self::assertCount($count, array_filter($this->reported, static fn (MfaEvent $event): bool => $event instanceof VerificationPassed));
    }
}
