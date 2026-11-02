<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Drivers\Base32;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpParameters;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use Tests\Fixtures\Drivers\AuthenticatorApp;
use Tests\Fixtures\Drivers\HeaderApplicationResolver;
use Tests\Fixtures\Factors\TotpStubFactor;
use Tests\Fixtures\Factors\UnrecordableTotpFactor;
use Tests\TestCase;

/**
 * Unit tests for `TotpDriver`: the RFC 6238 test vectors, the window and the
 * application's own, the single use of a time step at verification and
 * confirmation, the secrets and parameters of a new enrolment, and the
 * provisioning URI.
 *
 * Time is frozen in the middle of a step, so no assertion straddles a step
 * boundary. At that moment the authenticator app's secret shows `768147`, and
 * `385088` and `050219` one step before and after.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TotpDriver::class)]
final class TotpDriverTest extends TestCase
{
    /** @var int The frozen time: 15 seconds into time step 60000000. */
    private const int NOW = 1800000015;

    /** @var int The time step the frozen time falls in. */
    private const int STEP = 60000000;

    /** @var string The code the authenticator app shows at the frozen time. */
    private const string CODE = '768147';

    /** @var string The account name used across the provisioning URI tests. */
    private const string ACCOUNT_NAME = 'user@example.com';

    /**
     * Freeze time in the middle of a step.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->travelTo(CarbonImmutable::createFromTimestamp(self::NOW));
    }

    /**
     * The code the app shows now verifies, and its step is recorded.
     *
     * @return void
     */
    public function testAcceptsTheCurrentCodeAndRecordsItsStep(): void
    {
        $factor = $this->factor();

        self::assertSame(CodeCheck::ACCEPTED, $this->driver()->verify($factor, self::CODE, self::binding()));
        self::assertSame(self::STEP, $factor->getLastAcceptedStep());
    }

    /**
     * Rows of `[algorithm, key, time, code]`: RFC 6238 Appendix B, 8 digits.
     *
     * @return iterable<string, array{string, string, int, string}>
     */
    public static function rfc6238Vectors(): iterable
    {
        $keys = [
            'sha1'   => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
            'sha256' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
            'sha512' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA',
        ];

        $vectors = [
            59          => ['94287082', '46119246', '90693936'],
            1111111109  => ['07081804', '68084774', '25091201'],
            1111111111  => ['14050471', '67062674', '99943326'],
            1234567890  => ['89005924', '91819424', '93441116'],
            2000000000  => ['69279037', '90698825', '38618901'],
            20000000000 => ['65353130', '77737706', '47863826'],
        ];

        foreach ($vectors as $time => $codes) {
            foreach (array_keys($keys) as $index => $algorithm) {
                yield sprintf('%s at %d', $algorithm, $time) => [$algorithm, $keys[$algorithm], $time, $codes[$index]];
            }
        }
    }

    /**
     * Each published code verifies at its time against a factor enrolled with
     * the published key, and only in its own step.
     *
     * @param  string  $algorithm
     * @param  string  $key
     * @param  int  $time
     * @param  string  $code
     * @return void
     */
    #[DataProvider('rfc6238Vectors')]
    public function testVerifiesTheRfc6238Vector(string $algorithm, string $key, int $time, string $code): void
    {
        $this->configuration()->set('mfa.totp.window', 0);

        $this->travelTo(CarbonImmutable::createFromTimestamp($time));

        self::assertSame(CodeCheck::ACCEPTED, $this->driver()->verify(new TotpStubFactor($key, $algorithm, 8), $code, self::binding()));

        $this->travelTo(CarbonImmutable::createFromTimestamp($time + 30));

        self::assertNotSame(CodeCheck::ACCEPTED, $this->driver()->verify(new TotpStubFactor($key, $algorithm, 8), $code, self::binding()));
    }

    /**
     * The default window accepts a code from one step either side of the
     * current one, and refuses one from two steps away.
     *
     * @return void
     */
    public function testTheDefaultWindowAcceptsOneStepEitherSideOnly(): void
    {
        self::assertSame(CodeCheck::ACCEPTED, $this->driver()->verify($this->factor(), '385088', self::binding()));
        self::assertSame(CodeCheck::ACCEPTED, $this->driver()->verify($this->factor(), '050219', self::binding()));
        self::assertNotSame(CodeCheck::ACCEPTED, $this->driver()->verify($this->factor(), '168521', self::binding()));
        self::assertNotSame(CodeCheck::ACCEPTED, $this->driver()->verify($this->factor(), '687638', self::binding()));
    }

    /**
     * The window is read from the configuration on every call: a driver built
     * before it changes applies the new one.
     *
     * @return void
     */
    public function testTheWindowIsReadOnEveryCall(): void
    {
        $driver = $this->driver();

        $this->configuration()->set('mfa.totp.window', 0);

        self::assertNotSame(CodeCheck::ACCEPTED, $driver->verify($this->factor(), '385088', self::binding()));
        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($this->factor(), self::CODE, self::binding()));

        $this->configuration()->set('mfa.totp.window', 3);

        $factor = $this->factor();

        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($factor, AuthenticatorApp::code($factor, -3), self::binding()));
        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($factor, AuthenticatorApp::code($factor, 3), self::binding()));
        self::assertNotSame(CodeCheck::ACCEPTED, $driver->verify($this->factor(), AuthenticatorApp::code($factor, 4), self::binding()));
    }

    /**
     * A verification's window is the `totp_window` of the application its
     * binding names, through a driver built once; an application that sets
     * none, or is not configured, takes the package-wide window.
     *
     * @return void
     */
    public function testAVerificationsWindowIsItsBindingsApplications(): void
    {
        $this->configuration()->set('mfa.applications', [
            'strict'  => ['totp_window' => 0],
            'lenient' => ['totp_window' => 2],
        ]);

        $driver = $this->driver();
        $factor = $this->factor();

        self::assertSame(CodeCheck::INVALID, $driver->verify($this->factor(), '385088', self::binding('strict')));
        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($this->factor(), self::CODE, self::binding('strict')));

        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($this->factor(), AuthenticatorApp::code($factor, -2), self::binding('lenient')));
        self::assertSame(CodeCheck::INVALID, $driver->verify($this->factor(), AuthenticatorApp::code($factor, -3), self::binding('lenient')));

        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($this->factor(), '385088', self::binding('unconfigured')));
        self::assertSame(CodeCheck::INVALID, $driver->verify($this->factor(), AuthenticatorApp::code($factor, -2), self::binding('unconfigured')));
    }

    /**
     * A confirmation's window is the `totp_window` of the application its
     * binding names, whichever application the request is for.
     *
     * @return void
     */
    public function testAConfirmationsWindowIsItsBindingsApplicationsOwn(): void
    {
        $this->configuration()->set('mfa.applications', [
            'strict'  => ['totp_window' => 0],
            'lenient' => ['totp_window' => 2],
        ]);

        $this->container()->instance(ApplicationResolver::class, new HeaderApplicationResolver);

        $driver = $this->driver();
        $factor = $this->factor();

        $this->requestFor('lenient');

        self::assertSame(CodeCheck::INVALID, $driver->confirm($this->factor(), AuthenticatorApp::code($factor, 2), self::binding('strict')));

        $this->requestFor('strict');

        self::assertSame(CodeCheck::ACCEPTED, $driver->confirm($this->factor(), AuthenticatorApp::code($factor, 2), self::binding('lenient')));
    }

    /**
     * Failures never widen the window.
     *
     * @return void
     */
    public function testTheWindowNeverWidensAfterFailures(): void
    {
        $driver = $this->driver();
        $factor = $this->factor();

        for ($attempt = 0; $attempt < 10; $attempt++) {
            self::assertNotSame(CodeCheck::ACCEPTED, $driver->verify($factor, '000000', self::binding()));
        }

        self::assertNotSame(CodeCheck::ACCEPTED, $driver->verify($factor, '687638', self::binding()));
        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($factor, self::CODE, self::binding()));
    }

    /**
     * The same code, and so the same step, is accepted once.
     *
     * @return void
     */
    public function testRefusesTheSameStepTwice(): void
    {
        $driver = $this->driver();
        $factor = $this->factor();

        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($factor, self::CODE, self::binding()));
        self::assertSame(CodeCheck::REPLAYED, $driver->verify($factor, self::CODE, self::binding()));
        self::assertSame(self::STEP, $factor->getLastAcceptedStep());
    }

    /**
     * Once a code is accepted, a code for an earlier step of the window is
     * refused, though it is still in the window.
     *
     * @return void
     */
    public function testRefusesAnEarlierStepOnceALaterOneIsAccepted(): void
    {
        $driver = $this->driver();
        $factor = $this->factor();

        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($factor, '050219', self::binding()));
        self::assertSame(CodeCheck::REPLAYED, $driver->verify($factor, self::CODE, self::binding()));
        self::assertSame(CodeCheck::REPLAYED, $driver->verify($factor, '385088', self::binding()));
        self::assertSame(self::STEP + 1, $factor->getLastAcceptedStep());
    }

    /**
     * Codes for later and later steps are each accepted, and the step each
     * matched is the one recorded.
     *
     * @return void
     */
    public function testAcceptsEachLaterStepAndRecordsTheStepItMatched(): void
    {
        $driver = $this->driver();
        $factor = $this->factor();

        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($factor, '385088', self::binding()));
        self::assertSame(self::STEP - 1, $factor->getLastAcceptedStep());

        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($factor, self::CODE, self::binding()));
        self::assertSame(self::STEP, $factor->getLastAcceptedStep());

        self::assertSame(CodeCheck::ACCEPTED, $driver->verify($factor, '050219', self::binding()));
        self::assertSame(self::STEP + 1, $factor->getLastAcceptedStep());
    }

    /**
     * Confirming records the step as verifying does, so the confirming code is
     * refused at the next verification, and at a second confirmation.
     *
     * @return void
     */
    public function testTheConfirmingCodeIsRefusedAtTheNextVerification(): void
    {
        $driver = $this->driver();
        $factor = $this->factor();

        self::assertSame(CodeCheck::ACCEPTED, $driver->confirm($factor, self::CODE, self::binding()));
        self::assertSame(self::STEP, $factor->getLastAcceptedStep());
        self::assertSame(CodeCheck::REPLAYED, $driver->verify($factor, self::CODE, self::binding()));
        self::assertSame(CodeCheck::REPLAYED, $driver->confirm($factor, self::CODE, self::binding()));
    }

    /**
     * A code matching no step of the window, or of another length, is refused
     * and records nothing.
     *
     * @return void
     */
    public function testRefusesAWrongCodeAndRecordsNothing(): void
    {
        $driver = $this->driver();
        $factor = $this->factor();

        foreach (['000000', '76814', '7681470', ' 768147', ''] as $code) {
            self::assertNotSame(CodeCheck::ACCEPTED, $driver->verify($factor, $code, self::binding()), $code);
        }

        self::assertNull($factor->getLastAcceptedStep());
    }

    /**
     * Rows of `[secret]` a factor cannot verify with.
     *
     * @return iterable<string, array{?string}>
     */
    public static function unusableSecrets(): iterable
    {
        yield 'no secret' => [null];
        yield 'an empty secret' => [''];
        yield 'padding alone' => ['===='];
        yield 'not Base32' => ['GEZDGNBVGY3TQOJQ!'];
    }

    /**
     * A factor without a usable secret verifies nothing.
     *
     * @param  ?string  $secret
     * @return void
     */
    #[DataProvider('unusableSecrets')]
    public function testRefusesAFactorWithoutAUsableSecret(?string $secret): void
    {
        self::assertNotSame(CodeCheck::ACCEPTED, $this->driver()->verify(new TotpStubFactor($secret), self::CODE, self::binding()));
    }

    /**
     * An empty secret is refused even with the code an empty key makes, which
     * anyone could compute.
     *
     * @return void
     */
    public function testRefusesAnEmptySecretEvenWithTheCodeAnEmptyKeyMakes(): void
    {
        $parameters = new TotpParameters('sha1', 6, 30);

        self::assertNotSame(CodeCheck::ACCEPTED, $this->driver()->verify(new TotpStubFactor(''), $parameters->code('', self::STEP), self::binding()));
        self::assertNotSame(CodeCheck::ACCEPTED, $this->driver()->verify(new TotpStubFactor('===='), $parameters->code('', self::STEP), self::binding()));
    }

    /**
     * Rows of `[algorithm, digits, period]` a factor cannot verify with.
     *
     * @return iterable<string, array{?string, ?int, ?int}>
     */
    public static function unusableParameters(): iterable
    {
        yield 'no algorithm' => [null, 6, 30];
        yield 'no digits' => ['sha1', null, 30];
        yield 'no period' => ['sha1', 6, null];
        yield 'an unknown algorithm' => ['md5', 6, 30];
        yield 'too many digits' => ['sha1', 9, 30];
    }

    /**
     * A factor that holds no parameters, or parameters out of bounds, verifies
     * nothing, rather than taking the configured ones.
     *
     * @param  ?string  $algorithm
     * @param  ?int  $digits
     * @param  ?int  $period
     * @return void
     */
    #[DataProvider('unusableParameters')]
    public function testRefusesAFactorWithoutUsableParameters(?string $algorithm, ?int $digits, ?int $period): void
    {
        self::assertNotSame(CodeCheck::ACCEPTED, $this->driver()->verify(new TotpStubFactor(AuthenticatorApp::SECRET, $algorithm, $digits, $period), self::CODE, self::binding()));
    }

    /**
     * A factor with nowhere to record an accepted step cannot be held to single
     * use, so even its current code is refused.
     *
     * @return void
     */
    public function testRefusesAFactorThatCannotRecordAStep(): void
    {
        self::assertNotSame(CodeCheck::ACCEPTED, $this->driver()->verify(new UnrecordableTotpFactor, self::CODE, self::binding()));
        self::assertNotSame(CodeCheck::ACCEPTED, $this->driver()->confirm(new UnrecordableTotpFactor, self::CODE, self::binding()));
    }

    /**
     * Rows of `[algorithm, bytes]`: the length of a new secret.
     *
     * @return iterable<string, array{string, int}>
     */
    public static function secretLengths(): iterable
    {
        yield 'sha1' => ['sha1', 20];
        yield 'sha256' => ['sha256', 32];
        yield 'sha512' => ['sha512', 64];
    }

    /**
     * A new secret is random, in Base32, and as long as the configured
     * algorithm's output.
     *
     * @param  string  $algorithm
     * @param  int  $bytes
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('secretLengths')]
    public function testANewSecretIsAsLongAsTheAlgorithmOutput(string $algorithm, int $bytes): void
    {
        $this->configuration()->set('mfa.totp.algorithm', $algorithm);

        $secret = $this->driver()->startEnrollment(new TotpStubFactor(null));
        $other  = $this->driver()->startEnrollment(new TotpStubFactor(null));

        self::assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret->reveal());
        self::assertSame($bytes, strlen((string) Base32::decode($secret->reveal())));
        self::assertNotSame($secret->reveal(), $other->reveal());
    }

    /**
     * Starting an enrolment stamps the configured parameters on the factor,
     * with no step accepted yet.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testStartingAnEnrollmentStampsTheParametersOnTheFactor(): void
    {
        $this->configuration()->set('mfa.totp', ['algorithm' => 'sha256', 'digits' => 8, 'period' => 60]);

        $factor = new Factor(['last_accepted_step' => 5]);

        $this->driver()->startEnrollment($factor);

        self::assertSame('sha256', $factor->getTotpAlgorithm());
        self::assertSame(8, $factor->getTotpDigits());
        self::assertSame(60, $factor->getTotpPeriod());
        self::assertNull($factor->getLastAcceptedStep());
    }

    /**
     * A factor enrolled with the configured parameters verifies the code its
     * app makes from the new secret with them, and keeps them after the
     * configuration changes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnEnrolledFactorKeepsItsParameters(): void
    {
        $this->configuration()->set('mfa.totp', ['algorithm' => 'sha512', 'digits' => 8, 'period' => 60]);

        $factor = new Factor;

        $factor->setAttribute('secret', $this->driver()->startEnrollment($factor)->reveal());

        $this->configuration()->set('mfa.totp', []);

        $code = AuthenticatorApp::code($factor);

        self::assertSame(8, strlen($code));
        self::assertSame(CodeCheck::ACCEPTED, $this->driver()->confirm($factor, $code, self::binding()));
        self::assertSame(intdiv(self::NOW, 60), $factor->getLastAcceptedStep());
    }

    /**
     * The parameters of a new enrolment are the configured ones.
     *
     * @return void
     */
    public function testTheParametersAreTheConfiguredOnes(): void
    {
        $this->configuration()->set('mfa.totp', ['algorithm' => 'sha256', 'digits' => 7, 'period' => 45]);

        $parameters = $this->driver()->parameters();

        self::assertSame(['sha256', 7, 45], [$parameters->algorithm, $parameters->digits, $parameters->period]);
    }

    /**
     * The provisioning URI is in the `otpauth://` key URI format, with the
     * label, the secret, the issuer and the factor's parameters.
     *
     * @return void
     */
    public function testTheProvisioningUriCarriesTheLabelSecretAndParameters(): void
    {
        $uri = $this->driver()->provisioningUri($this->factor(), 'Acme', self::ACCOUNT_NAME, new RevealedSecret(AuthenticatorApp::SECRET));

        self::assertSame('otpauth://totp/Acme:user%40example.com?secret=' . AuthenticatorApp::SECRET . '&issuer=Acme&algorithm=SHA1&digits=6&period=30', $uri->reveal());
    }

    /**
     * The provisioning URI carries the factor's own parameters, not the
     * configured ones.
     *
     * @return void
     */
    public function testTheProvisioningUriCarriesTheFactorsOwnParameters(): void
    {
        $factor = new TotpStubFactor(AuthenticatorApp::SECRET, 'sha256', 8, 60);

        $uri = $this->driver()->provisioningUri($factor, 'Acme', self::ACCOUNT_NAME, new RevealedSecret(AuthenticatorApp::SECRET));

        self::assertStringEndsWith('&algorithm=SHA256&digits=8&period=60', $uri->reveal());
    }

    /**
     * An issuer holding a space is encoded once, in the label and the query.
     *
     * @return void
     */
    public function testTheProvisioningUriEncodesTheIssuerOnce(): void
    {
        $uri = $this->driver()->provisioningUri($this->factor(), 'Acme Co', self::ACCOUNT_NAME, new RevealedSecret(AuthenticatorApp::SECRET))->reveal();

        self::assertStringStartsWith('otpauth://totp/Acme%20Co:user%40example.com?', $uri);
        self::assertStringContainsString('&issuer=Acme%20Co&', $uri);
        self::assertStringNotContainsString('%2520', $uri);
    }

    /**
     * Rows of `[issuer, account name, message]` a provisioning URI refuses.
     *
     * @return iterable<string, array{string, string, string}>
     */
    public static function unusableNames(): iterable
    {
        $issuer  = 'The issuer of a provisioning URI must not be empty or hold a colon.';
        $account = 'The account name of a provisioning URI must not be empty or hold a colon.';

        yield 'an empty issuer' => ['', self::ACCOUNT_NAME, $issuer];
        yield 'an issuer with a colon' => ['Acme:Co', self::ACCOUNT_NAME, $issuer];
        yield 'an empty account name' => ['Acme', '', $account];
        yield 'an account name with colon' => ['Acme', 'user:name', $account];
    }

    /**
     * An empty issuer or account name, or one holding the colon that separates
     * them in the label, is refused.
     *
     * @param  string  $issuer
     * @param  string  $accountName
     * @param  string  $message
     * @return void
     */
    #[DataProvider('unusableNames')]
    public function testTheProvisioningUriRefusesAnUnusableName(string $issuer, string $accountName, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $this->driver()->provisioningUri($this->factor(), $issuer, $accountName, new RevealedSecret(AuthenticatorApp::SECRET));
    }

    /**
     * A factor whose enrolment has not started has no parameters to put in a
     * provisioning URI.
     *
     * @return void
     */
    public function testTheProvisioningUriRefusesAFactorWithoutParameters(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The factor holds no TOTP parameters; start its enrolment first.');

        $this->driver()->provisioningUri(new TotpStubFactor(AuthenticatorApp::SECRET, null), 'Acme', self::ACCOUNT_NAME, new RevealedSecret(AuthenticatorApp::SECRET));
    }

    /**
     * The secret and code parameters carry `#[\SensitiveParameter]`, so they
     * never reach a stack trace.
     *
     * @return void
     */
    public function testSecretsAndCodesAreSensitiveParameters(): void
    {
        foreach (['provisioningUri' => 3, 'verify' => 1, 'confirm' => 1] as $method => $position) {
            $parameter = (new \ReflectionMethod(TotpDriver::class, $method))->getParameters()[$position] ?? null;

            self::assertNotNull($parameter);
            self::assertNotEmpty($parameter->getAttributes(\SensitiveParameter::class), $method);
        }
    }

    /**
     * What a verification through the driver is bound to.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(string $application = 'web'): ProofBinding
    {
        return new ProofBinding('user', '1', $application, 'sign-in-1', Purpose::STEP_UP);
    }

    /**
     * Make the current request one for the named application.
     *
     * @param  string  $application
     * @return void
     */
    private function requestFor(string $application): void
    {
        $this->container()->instance('request', HeaderApplicationResolver::requestFor($application));
    }

    /**
     * Build the driver over the application's configuration.
     *
     * @return \SineMacula\Laravel\Mfa\Drivers\TotpDriver
     */
    private function driver(): TotpDriver
    {
        return new TotpDriver(new TotpSettings($this->configuration()));
    }

    /**
     * Build a factor enrolled in the authenticator app with the default
     * parameters and no step accepted.
     *
     * @return \Tests\Fixtures\Factors\TotpStubFactor
     */
    private function factor(): TotpStubFactor
    {
        return new TotpStubFactor(AuthenticatorApp::SECRET);
    }

    /**
     * The application's configuration.
     *
     * @return \Illuminate\Config\Repository
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function configuration(): Repository
    {
        return $this->container()->make(Repository::class);
    }
}
