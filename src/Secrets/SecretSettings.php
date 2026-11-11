<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Contracts\Config\Repository;

/**
 * The `mfa.secrets` settings. Redaction fails safe: only a value that reads as
 * false turns it off, so a missing or malformed value leaves it on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SecretSettings
{
    /** @var string */
    private const string REDACT = 'mfa.secrets.redact';

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call. */
        private Repository $config,
    ) {}

    /**
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
