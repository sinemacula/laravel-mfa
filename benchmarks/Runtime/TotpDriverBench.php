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
 * Every step of the window is compared, so a code in it and one outside should
 * cost the same; both answer `INVALID`, as `ACCEPTED` needs the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AfterMethods('releaseClock')]
#[BeforeMethods('setUp')]
final class TotpDriverBench
{
    /** @var string */
    private const string APPLICATION = 'web';

    /** @var \SineMacula\Laravel\Mfa\Drivers\TotpSettings */
    private readonly TotpSettings $settings;

    /** @var \SineMacula\Laravel\Mfa\Drivers\TotpDriver */
    private readonly TotpDriver $driver;

    /** @var \Benchmarks\Support\TotpFactor */
    private readonly TotpFactor $factor;

    /** @var \SineMacula\Laravel\Mfa\Proofs\ProofBinding */
    private readonly ProofBinding $binding;

    /** @var string */
    private string $matching = '';

    /** @var string */
    private string $mismatched = '';

    /**
     * @return void
     */
    public function __construct()
    {
        $this->settings = new TotpSettings(new Repository);
        $this->driver   = new TotpDriver($this->settings);
        $this->factor   = new TotpFactor(AuthenticatorApp::SECRET);
        $this->binding  = new ProofBinding('user', '1', self::APPLICATION, 'sign-in-1', Purpose::STEP_UP);
    }

    /**
     * Freeze the clock so no step boundary is crossed, and prove both codes.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function setUp(): void
    {
        CarbonImmutable::setTestNow('2026-11-01 12:00:00');

        $window = $this->windowCodes($this->settings->windowFor(self::APPLICATION));

        $this->matching   = $window[0];
        $this->mismatched = self::firstCodeOutside($window);

        foreach ([$this->matching, $this->mismatched] as $code) {
            BenchOutcome::assert('TOTP window', $this->driver->verify($this->factor, $code, $this->binding) === CodeCheck::INVALID);
        }

        BenchOutcome::assert('TOTP window', in_array($this->matching, $window, true) && !in_array($this->mismatched, $window, true));
    }

    /**
     * @return void
     */
    public function releaseClock(): void
    {
        CarbonImmutable::setTestNow();
    }

    /**
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
