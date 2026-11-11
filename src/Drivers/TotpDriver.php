<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\ProvisioningDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * TOTP (RFC 6238). The window comes from the binding's application, not the
 * request, and every step is compared so timing does not reveal a match.
 *
 * A step is single-use per factor (RFC 6238 section 5.2) through a
 * compare-and-set, so a factor that cannot record one verifies nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TotpDriver implements ProvisioningDriver
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Drivers\TotpSettings  $settings
     */
    public function __construct(

        /** Read per call. */
        private TotpSettings $settings,
    ) {}

    /**
     * Records the matched step so it is never accepted again; a step already
     * passed is `REPLAYED`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function verify(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
    {
        $step = $this->matchedStep($factor, $code, $binding->application);

        if ($step === null || !$factor instanceof EloquentFactor) {
            return CodeCheck::INVALID;
        }

        return $factor->storeAcceptedStep($step) ? CodeCheck::ACCEPTED : CodeCheck::REPLAYED;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::AUTHENTICATOR_APP;
    }

    /**
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return ['otp'];
    }

    /**
     * A new shared secret. A non-Eloquent factor gets its parameters from its
     * caller, through `parameters()`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return \SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    #[\Override]
    public function startEnrollment(Factor $factor): RevealedSecret
    {
        $parameters = $this->parameters();

        if ($factor instanceof EloquentFactor && $factor instanceof Model) {
            $factor->setAttribute($factor->getTotpAlgorithmName(), $parameters->algorithm);
            $factor->setAttribute($factor->getTotpDigitsName(), $parameters->digits);
            $factor->setAttribute($factor->getTotpPeriodName(), $parameters->period);
            $factor->setAttribute($factor->getLastAcceptedStepName(), null);
        }

        return new RevealedSecret(Base32::encode(random_bytes($parameters->secretLength())));
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
    {
        return $this->verify($factor, $code, $binding);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Drivers\TotpParameters
     *
     * @throws \InvalidArgumentException
     */
    public function parameters(): TotpParameters
    {
        return $this->settings->parameters();
    }

    /**
     * An `otpauth://` URI. Pass the issuer and account name unencoded; neither
     * may be empty or hold a colon.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $issuer
     * @param  string  $accountName
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $secret
     * @return \SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function provisioningUri(Factor $factor, string $issuer, string $accountName, #[\SensitiveParameter] RevealedSecret $secret): RevealedSecret
    {
        $parameters = TotpParameters::fromFactor($factor);

        if ($parameters === null) {
            throw new \InvalidArgumentException('The factor holds no TOTP parameters; start its enrolment first.');
        }

        foreach (['issuer' => $issuer, 'account name' => $accountName] as $name => $value) {
            if ($value === '' || str_contains($value, ':')) {
                throw new \InvalidArgumentException(sprintf('The %s of a provisioning URI must not be empty or hold a colon.', $name));
            }
        }

        $query = http_build_query([
            'secret'    => $secret->reveal(),
            'issuer'    => $issuer,
            'algorithm' => strtoupper($parameters->algorithm),
            'digits'    => $parameters->digits,
            'period'    => $parameters->period,
        ], '', '&', PHP_QUERY_RFC3986);

        return new RevealedSecret(sprintf('otpauth://totp/%s:%s?%s', rawurlencode($issuer), rawurlencode($accountName), $query));
    }

    /**
     * The latest matching step of the window. Every step is compared.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  string  $application
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    private function matchedStep(Factor $factor, #[\SensitiveParameter] string $code, string $application): ?int
    {
        $parameters = TotpParameters::fromFactor($factor);
        $key        = Base32::decode($factor->getSecret() ?? '');

        if ($parameters === null || $key === null || $key === '') {
            return null;
        }

        $window  = $this->settings->windowFor($application);
        $current = $parameters->stepAt(CarbonImmutable::now()->getTimestamp());
        $matched = null;

        for ($step = $current - $window; $step <= $current + $window; $step++) {
            if (!hash_equals($parameters->code($key, $step), $code)) {
                continue;
            }

            $matched = $step;
        }

        return $matched;
    }
}
