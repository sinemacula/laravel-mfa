<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * TOTP factor driver: time-based one-time passwords (RFC 6238) from an
 * authenticator app, computed by the package itself over `hash_hmac`.
 *
 * A new enrolment gets a secret of random bytes as long as its algorithm's
 * output (20 for SHA-1, 32 for SHA-256, 64 for SHA-512, never under 160 bits)
 * and the algorithm, digits and period `mfa.totp` sets for new enrolments,
 * which the factor keeps. A code is checked against every time step of the
 * window, `mfa.totp.window` steps either side of the current one, each compared
 * with `hash_equals()` and none skipped when an earlier one matches, so the
 * work does not depend on which step matches or whether one does. The window is
 * read from the configuration on every call and never widens.
 *
 * A time step is single-use per factor (RFC 6238 §5.2): a code is accepted only
 * when its step is later than the factor's last accepted one, recorded in the
 * same compare-and-set (see `EloquentFactor::storeAcceptedStep()`), at
 * confirmation as at verification. Of two requests with the same code, only one
 * records the step, and a code for an earlier step is refused. A factor that
 * cannot record a step, one implementing only the `Factor` read surface, cannot
 * be held to single use, so it verifies nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TotpDriver implements FactorDriver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Drivers\TotpSettings  $settings
     */
    public function __construct(

        /** The parameters of new enrolments and the window, read per call. */
        private TotpSettings $settings,
    ) {}

    /**
     * TOTP challenges are implicit: the authenticator app makes codes locally
     * from the shared secret, so there is nothing to send.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    #[\Override]
    public function issueChallenge(Factor $factor): void
    {
        // Nothing to send: the authenticator app makes the code.
    }

    /**
     * Verify the code against the factor's secret and parameters, recording the
     * matched time step so it is never accepted again.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        $step = $this->matchedStep($factor, $code);

        return $step !== null
            && $factor instanceof EloquentFactor
            && $factor->storeAcceptedStep($step);
    }

    /**
     * An authenticator app holds the shared secret.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::AUTHENTICATOR_APP;
    }

    /**
     * The `amr` value of a TOTP code: `otp`.
     *
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return ['otp'];
    }

    /**
     * Start an enrolment with a new shared secret, which the caller stores on
     * the pending factor and shows the person once.
     *
     * The parameters new enrolments use are stamped on an Eloquent factor, with
     * no step accepted yet; a factor of another kind is given them by its
     * caller, from `parameters()`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    #[\Override]
    public function startEnrollment(Factor $factor): string
    {
        $parameters = $this->parameters();

        if ($factor instanceof EloquentFactor && $factor instanceof Model) {
            $factor->setAttribute($factor->getTotpAlgorithmName(), $parameters->algorithm);
            $factor->setAttribute($factor->getTotpDigitsName(), $parameters->digits);
            $factor->setAttribute($factor->getTotpPeriodName(), $parameters->period);
            $factor->setAttribute($factor->getLastAcceptedStepName(), null);
        }

        return Base32::encode(random_bytes($parameters->secretLength()));
    }

    /**
     * Confirm the pending factor with the first code its authenticator app
     * shows, checked as any other, so its step is recorded and the confirming
     * code cannot be used again.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    #[\Override]
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        return $this->verify($factor, $code);
    }

    /**
     * The algorithm, digits and period a new enrolment is made with, as
     * `mfa.totp` sets them now.
     *
     * @return \SineMacula\Laravel\Mfa\Drivers\TotpParameters
     *
     * @throws \InvalidArgumentException
     */
    public function parameters(): TotpParameters
    {
        return $this->settings->parameters();
    }

    /**
     * Build the factor's provisioning URI in the `otpauth://` key URI format,
     * for an authenticator app to read from a QR code: the label
     * `issuer:account` and the secret, issuer, algorithm, digits and period.
     * Pass the issuer and account name as they are, not encoded; neither may be
     * empty or hold a colon, which separates them in the label.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $issuer
     * @param  string  $accountName
     * @param  string  $secret
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function provisioningUri(Factor $factor, string $issuer, string $accountName, #[\SensitiveParameter] string $secret): string
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
            'secret'    => $secret,
            'issuer'    => $issuer,
            'algorithm' => strtoupper($parameters->algorithm),
            'digits'    => $parameters->digits,
            'period'    => $parameters->period,
        ], '', '&', PHP_QUERY_RFC3986);

        return sprintf('otpauth://totp/%s:%s?%s', rawurlencode($issuer), rawurlencode($accountName), $query);
    }

    /**
     * The latest time step of the window whose code is the one given, or `null`
     * when none is, or the factor has no usable secret or parameters. Every
     * step of the window is computed and compared.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    private function matchedStep(Factor $factor, #[\SensitiveParameter] string $code): ?int
    {
        $parameters = TotpParameters::fromFactor($factor);
        $key        = Base32::decode($factor->getSecret() ?? '');

        if ($parameters === null || $key === null || $key === '') {
            return null;
        }

        $window  = $this->settings->window();
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
