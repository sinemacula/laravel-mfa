<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchApplication;
use Benchmarks\Support\BenchOutcome;
use Benchmarks\Support\BenchProofs;
use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Http\Request;
use PhpBench\Attributes\AfterMethods;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\ParamProviders;
use PhpBench\Attributes\Revs;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Assurance\SessionProofs;

/**
 * The requirement check two ways: `ProofRequirementCheck::check()` with no
 * database, and a request the `mfa` middleware lets on, on the application the
 * query budgets use in `always` mode, so with the statements they count.
 *
 * The middleware only reads, so unlike a verification it can be measured over
 * ordinary revolutions. It is called directly, so the route and the kernel are
 * not measured.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RequirementCheckBench
{
    /** @var string The name of a session with as many proofs as it can keep. */
    private const string LONG_SESSION = 'long session';

    /** @var string The name of a session with one proof after its first factor. */
    private const string ONE_PROOF = 'first factor and one proof';

    /** @var \SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck */
    private ProofRequirementCheck $check;

    /** @var \SineMacula\Laravel\Mfa\Requirements\Requirement */
    private Requirement $requirement;

    /** @var list<\SineMacula\Laravel\Mfa\Proofs\Proof> */
    private array $proofs = [];

    /** @var ?\SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet The middleware, once its application is arranged. */
    private ?EnsureMfaRequirementIsMet $gate = null;

    /** @var \Illuminate\Http\Request */
    private Request $request;

    /**
     * Build the check over the default policy, and the request the middleware
     * is given.
     *
     * @return void
     */
    public function __construct()
    {
        $container = new Container;

        $container->instance(CombinationPolicy::class, new DefaultCombinationPolicy);

        $this->check       = new ProofRequirementCheck($container);
        $this->requirement = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2);
        $this->request     = Request::create('/');
    }

    /**
     * The sessions the check judges, by name.
     *
     * @return iterable<string, array{session: string}>
     */
    public function provideSessions(): iterable
    {
        foreach ([self::ONE_PROOF, self::LONG_SESSION] as $session) {
            yield $session => ['session' => $session];
        }
    }

    /**
     * Freeze the clock and prove the session meets AAL2.
     *
     * @param  array{session: string}  $params
     * @return void
     *
     * @throws \LogicException
     */
    public function arrangeCheck(array $params): void
    {
        CarbonImmutable::setTestNow(SessionProofs::now());

        $this->proofs = $params['session'] === self::LONG_SESSION ? BenchProofs::longSession() : BenchProofs::firstFactorAndTotp();

        BenchOutcome::assert('requirement check over ' . $params['session'], $this->check->check($this->requirement, ...$this->proofs)->meetsRequirement());
    }

    /**
     * Build the application, verify a person and prove the middleware lets the
     * request on, which also warms the path.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function arrangeGate(): void
    {
        BenchApplication::freezeClock();

        $app = BenchApplication::create('always');

        FakeEmailSender::fake($app);

        $user   = BenchApplication::signedInPerson($app, 'gated@example.test', '198.51.100.3', 'bench-gate');
        $factor = BenchApplication::totpFactor($user);
        $result = $app->make('mfa')->verify(CallerContext::fromRequest($app->make(Request::class), null, $app), Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        BenchOutcome::assert('requirement gate', $result->isVerified());

        $this->gate = $app->make(EnsureMfaRequirementIsMet::class);

        BenchOutcome::assert('requirement gate', $this->pass()->getStatusCode() === Response::HTTP_OK);
    }

    /**
     * Release the clock.
     *
     * @return void
     */
    public function releaseClock(): void
    {
        BenchApplication::releaseClock();
    }

    /**
     * Measure judging the session's proofs.
     *
     * @return void
     */
    #[AfterMethods('releaseClock')]
    #[BeforeMethods('arrangeCheck')]
    #[Iterations(3)]
    #[ParamProviders('provideSessions')]
    #[Revs(100)]
    public function benchCheck(): void
    {
        $this->check->check($this->requirement, ...$this->proofs);
    }

    /**
     * Measure a request the middleware lets on.
     *
     * @return void
     */
    #[AfterMethods('releaseClock')]
    #[BeforeMethods('arrangeGate')]
    #[Iterations(3)]
    #[Revs(100)]
    public function benchGate(): void
    {
        $this->pass();
    }

    /**
     * The request, through the middleware alone.
     *
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \LogicException
     */
    private function pass(): Response
    {
        $gate = $this->gate ?? throw new \LogicException('The subject arranged no middleware.');

        return $gate->handle($this->request, static fn (): Response => new Response);
    }
}
