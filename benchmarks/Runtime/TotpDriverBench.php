<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchOutcome;
use Benchmarks\Support\TotpFactor;
use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use PhpBench\Attributes\AfterMethods;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use SineMacula\Laravel\Mfa\Drivers\Base32;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpParameters;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;

/**
 * The window comparison of the TOTP driver: every time step of the window is
 * computed and compared whether or not one matches, so a code in the window and
 * one outside it should cost the same.
 *
 * The factor is not an Eloquent one and has nowhere to record a step, so both
 * subjects answer `INVALID`: this measures the comparison, and `ACCEPTED`, with
 * the database's compare-and-set, is timed only by `VerificationBench`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AfterMethods('releaseClock')]
#[BeforeMethods('setUp')]
final class TotpDriverBench
{
    /** @var string The application the binding names. */
    private const string APPLICATION = 'web';

    /** @var \SineMacula\Laravel\Mfa\Drivers\TotpDriver */
    private TotpDriver $driver;

    /** @var \Benchmarks\Support\TotpFactor */
    private TotpFactor $factor;

    /** @var \SineMacula\Laravel\Mfa\Proofs\ProofBinding */
    private ProofBinding $binding;

    /** @var string A code of the window. */
    private string $matching = '';

    /** @var string A code outside the window. */
    private string $mismatched = '';

    /**
     * Freeze the clock at a fixed time, so no step boundary is crossed, and
     * prove each code is on its side of the window and answers `INVALID`.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function setUp(): void
    {
        CarbonImmutable::setTestNow('2026-11-01 12:00:00');

        $settings = new TotpSettings(new Repository);

        $this->driver  = new TotpDriver($settings);
        $this->factor  = new TotpFactor(AuthenticatorApp::SECRET);
        $this->binding = new ProofBinding('user', '1', self::APPLICATION, 'sign-in-1', Purpose::STEP_UP);

        $window = $this->windowCodes($settings->windowFor(self::APPLICATION));

        $this->matching   = $window[0];
        $this->mismatched = self::firstCodeOutside($window);

        foreach ([$this->matching, $this->mismatched] as $code) {
            BenchOutcome::assert('TOTP window', $this->driver->verify($this->factor, $code, $this->binding) === CodeCheck::INVALID);
        }

        BenchOutcome::assert('TOTP window', in_array($this->matching, $window, true) && !in_array($this->mismatched, $window, true));
    }

    /**
     * Release the clock.
     *
     * @return void
     */
    public function releaseClock(): void
    {
        CarbonImmutable::setTestNow();
    }

    /**
     * Measure comparing a code that matches a step of the window.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchWindowWithMatchingCode(): void
    {
        $this->driver->verify($this->factor, $this->matching, $this->binding);
    }

    /**
     * Measure comparing a code that matches no step of the window.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchWindowWithMismatchedCode(): void
    {
        $this->driver->verify($this->factor, $this->mismatched, $this->binding);
    }

    /**
     * The first six-digit code that is none of those given.
     *
     * @param  list<string>  $codes
     * @return string
     */
    private static function firstCodeOutside(array $codes): string
    {
        $candidate = 0;

        while (in_array(sprintf('%06d', $candidate), $codes, true)) {
            $candidate++;
        }

        return sprintf('%06d', $candidate);
    }

    /**
     * Every code of the window around now, from the factor's parameters.
     *
     * @param  int  $window
     * @return list<string>
     */
    private function windowCodes(int $window): array
    {
        $parameters = new TotpParameters($this->factor->getTotpAlgorithm(), $this->factor->getTotpDigits(), $this->factor->getTotpPeriod());
        $key        = (string) Base32::decode($this->factor->getSecret());
        $current    = $parameters->stepAt(CarbonImmutable::now()->getTimestamp());

        return array_map(static fn (int $step): string => $parameters->code($key, $step), range($current - $window, $current + $window));
    }
}
