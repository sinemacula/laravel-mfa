<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Contracts\Config\Repository;

/**
 * The secrets settings in `mfa.secrets`, read on every call: whether the
 * package redacts secrets from logs and reported exceptions. Redaction fails
 * safe: only a value that reads as false (`false`, `0`, `off`, `no`) turns it
 * off, and anything else, a missing or malformed value included, leaves it on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SecretSettings
{
    /** @var string The key of the redaction switch. */
    private const string REDACT = 'mfa.secrets.redact';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * Whether secrets are redacted from logs and reported exceptions: on unless
     * the setting reads as false.
     *
     * @return bool
     */
    public function redacts(): bool
    {
        $value = $this->config->get(self::REDACT, true);

        return $value === null
            || $value === ''
            || filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) !== false;
    }
}
