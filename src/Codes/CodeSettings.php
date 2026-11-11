<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The `mfa.codes` settings, read and bounds-checked on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeSettings
{
    /** @var string */
    private const string PREFIX = 'mfa.codes.';

    /** @var int Default resend cooldown, in seconds. */
    private const int RESEND_COOLDOWN_SECONDS = 60;

    /** @var int Default challenge lifetime, in minutes. */
    private const int CHALLENGE_TTL_MINUTES = 30;

    /** @var int Maximum challenge lifetime, in minutes. */
    private const int MAX_CHALLENGE_TTL_MINUTES = 60;

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, minimum and maximum per setting. */
    private const array NUMBERS = [
        'length'              => [6, 6, 10],
        'ttl_minutes'         => [10, 1, 10],
        'max_attempts'        => [5, 1, 10],
        'factor_send_limit'   => [5, 1, 50],
        'identity_send_limit' => [10, 1, 100],
        'send_window_minutes' => [60, 1, 1440],
    ];

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call. */
        private Repository $config,
    ) {}

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function length(): int
    {
        return $this->number('length');
    }

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function ttlMinutes(): int
    {
        return $this->number('ttl_minutes');
    }

    /**
     * Attempts per challenge; a resend keeps the count.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxAttempts(): int
    {
        return $this->number('max_attempts');
    }

    /**
     * Challenge lifetime from its first code, in minutes; resent codes never
     * outlive it.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function challengeTtlMinutes(): int
    {
        return IntegerSetting::read($this->config, self::PREFIX . 'challenge_ttl_minutes', self::CHALLENGE_TTL_MINUTES, $this->ttlMinutes(), self::MAX_CHALLENGE_TTL_MINUTES);
    }

    /**
     * Seconds before a challenge may resend.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function resendCooldownSeconds(): int
    {
        return IntegerSetting::read($this->config, self::PREFIX . 'resend_cooldown_seconds', self::RESEND_COOLDOWN_SECONDS, 0, $this->ttlMinutes() * 60);
    }

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function factorSendLimit(): int
    {
        return $this->number('factor_send_limit');
    }

    /**
     * Sends per identity in the window, across its factors and sessions.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function identitySendLimit(): int
    {
        return $this->number('identity_send_limit');
    }

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function sendWindowMinutes(): int
    {
        return $this->number('send_window_minutes');
    }

    /**
     * @return class-string<\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage>
     *
     * @throws \InvalidArgumentException
     */
    public function mailable(): string
    {
        $mailable = $this->config->get(self::PREFIX . 'mailable', MfaCodeMessage::class);

        if (!is_string($mailable) || !is_a($mailable, MfaCodeMessage::class, true)) {
            throw new \InvalidArgumentException(sprintf('%smailable must name %s or a subclass of it.', self::PREFIX, MfaCodeMessage::class));
        }

        return $mailable;
    }

    /**
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->length();
        $this->maxAttempts();
        $this->challengeTtlMinutes();
        $this->resendCooldownSeconds();
        $this->factorSendLimit();
        $this->identitySendLimit();
        $this->sendWindowMinutes();
        $this->mailable();
    }

    /**
     * @param  string  $key
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $key): int
    {
        [$default, $least, $most] = self::NUMBERS[$key];

        return IntegerSetting::read($this->config, self::PREFIX . $key, $default, $least, $most);
    }
}
