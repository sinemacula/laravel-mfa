<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;

/**
 * MFA manager.
 *
 * Manages multi-factor authentication drivers using Laravel's
 * Manager pattern. Provides convenience methods for checking MFA
 * status, setup state, and expiry for the current identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class MfaManager extends Manager
{
    /** @var string Cache key for the setup state */
    private const string CACHE_KEY_SETUP = 'setup';

    /** @var string Cache key for the factors collection */
    private const string CACHE_KEY_FACTORS = 'factors';

    /** @var array<string, mixed> Runtime cache for MFA state */
    private array $cache = [];

    /**
     * Get the default driver name.
     *
     * @return string
     */
    public function getDefaultDriver(): string
    {
        return 'totp';
    }

    /**
     * Determine whether the current identity should use multi-factor
     * authentication.
     *
     * Returns true when the identity's own preference requests MFA,
     * or when the bound `MfaPolicy` enforces it externally (for
     * example on every member of an organisation that mandates MFA).
     * The default policy binding (`NullMfaPolicy`) always returns
     * false, so standalone apps behave purely on the identity's own
     * `shouldUseMultiFactor()` preference.
     *
     * @return bool
     */
    public function shouldUse(): bool
    {
        $identity = Auth::user();

        if (!$identity instanceof MultiFactorAuthenticatable) {
            return false;
        }

        if ($identity->shouldUseMultiFactor()) {
            return true;
        }

        return $this->resolvePolicy()->shouldEnforce($identity);
    }

    /**
     * Determine whether the current identity has completed MFA
     * setup.
     *
     * An identity is considered set up when it has at least one
     * verified authentication factor. The result is cached for the
     * duration of the request.
     *
     * @return bool
     */
    public function isSetup(): bool
    {
        $identity = Auth::user();

        if (!$identity instanceof MultiFactorAuthenticatable) {
            return false;
        }

        return $this->cached(self::CACHE_KEY_SETUP, $identity, fn (): bool => $identity->isMfaEnabled());
    }

    /**
     * Determine whether the MFA verification has expired.
     *
     * Checks the session for the last MFA verification timestamp
     * and compares it against the configured or provided expiry
     * window.
     *
     * @param  int|null  $expiresAfter
     * @return bool
     */
    public function hasExpired(?int $expiresAfter = null): bool
    {
        /** @var \Illuminate\Session\Store $session */
        $session    = $this->container->make('session.store');
        $verifiedAt = $session->get('mfa_verified_at');

        if (!is_int($verifiedAt)) {
            return true;
        }

        if ($expiresAfter === null) {
            /** @var \Illuminate\Config\Repository $config */
            $config       = $this->container->make('config');
            $expiresAfter = $this->resolveIntConfig($config->get('mfa.default_expiry', 20160));
        }

        return (time() - $verifiedAt) > ($expiresAfter * 60);
    }

    /**
     * Clear the MFA state cache.
     *
     * Optionally scope the clear to a specific identity. When no
     * identity is provided, the entire cache is flushed.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null  $identity
     * @return void
     */
    public function clearCache(?Authenticatable $identity = null): void
    {
        if ($identity === null) {
            $this->cache = [];
            return;
        }

        $prefix = $this->getCachePrefix($identity);

        $this->cache = array_filter(
            $this->cache,
            fn (string $key): bool => !str_starts_with($key, $prefix),
            ARRAY_FILTER_USE_KEY,
        );
    }

    /**
     * Get the authentication factors for the current identity.
     *
     * Returns null if the identity does not support multi-factor
     * authentication. The result is cached for the duration of the
     * request.
     *
     * @formatter:off
     *
     * @return \Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>|null
     *
     * @formatter:on
     */
    public function getFactors(): ?Collection
    {
        $identity = Auth::user();

        if (!$identity instanceof MultiFactorAuthenticatable) {
            return null;
        }

        return $this->cached(self::CACHE_KEY_FACTORS, $identity, static fn (): Collection => $identity->authFactors()->get()->toBase());
    }

    /**
     * Create the TOTP driver.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    protected function createTotpDriver(): FactorDriver
    {
        /** @var array{window?: int} $config */
        $config = $this->getDriverConfig('totp');

        return new TotpDriver(
            window: $config['window'] ?? 1,
        );
    }

    /**
     * Create the email driver.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    protected function createEmailDriver(): FactorDriver
    {
        /** @var array{code_length?: int, expiry?: int, max_attempts?: int} $config */
        $config = $this->getDriverConfig('email');

        return new EmailDriver(
            codeLength: $config['code_length']   ?? 6,
            expiry: $config['expiry']            ?? 10,
            maxAttempts: $config['max_attempts'] ?? 3,
        );
    }

    /**
     * Create the SMS driver.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    protected function createSmsDriver(): FactorDriver
    {
        /** @var array{code_length?: int, expiry?: int, max_attempts?: int} $config */
        $config = $this->getDriverConfig('sms');

        return new SmsDriver(
            codeLength: $config['code_length']   ?? 6,
            expiry: $config['expiry']            ?? 10,
            maxAttempts: $config['max_attempts'] ?? 3,
        );
    }

    /**
     * Resolve the bound MFA policy.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MfaPolicy
     */
    protected function resolvePolicy(): MfaPolicy
    {
        /** @var \SineMacula\Laravel\Mfa\Contracts\MfaPolicy */
        return $this->container->make(MfaPolicy::class);
    }

    /**
     * Get the configuration for a specific driver.
     *
     * @param  string  $driver
     * @return array<string, mixed>
     */
    private function getDriverConfig(string $driver): array
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container->make('config');

        /** @var array<string, mixed> */
        return $config->get("mfa.drivers.{$driver}", []);
    }

    /**
     * Retrieve a cached value or compute and store it.
     *
     * @template T
     *
     * @param  string  $key
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  callable(): T  $callback
     * @return T
     */
    private function cached(string $key, Authenticatable $identity, callable $callback): mixed
    {
        $cacheKey = $this->getCachePrefix($identity) . $key;

        if (!array_key_exists($cacheKey, $this->cache)) {
            $this->cache[$cacheKey] = $callback();
        }

        return $this->cache[$cacheKey];
    }

    /**
     * Get the cache key prefix for the given identity.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return string
     */
    private function getCachePrefix(Authenticatable $identity): string
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container->make('config');

        /** @var string $prefix */
        $prefix = $config->get('mfa.cache_prefix', 'mfa:');

        $identifier = $identity->getAuthIdentifier();

        return $prefix . (is_string($identifier) || is_int($identifier) ? (string) $identifier : '') . ':';
    }

    /**
     * Resolve a config value to an integer.
     *
     * @param  mixed  $value
     * @return int
     */
    private function resolveIntConfig(mixed $value): int
    {
        if (is_int($value)) {
            return $value;
        }

        return is_numeric($value) ? (int) $value : 0;
    }
}
