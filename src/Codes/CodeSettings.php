<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * The delivered code settings in `mfa.codes`, read on every call and validated
 * as they are read: the length and lifetime of a code sent by SMS or email, how
 * many attempts one challenge allows and how long its resends may run, the
 * cooldown before another code may be sent, the caps on how many are sent, the
 * SMS message and the email message class. A value outside its bounds fails
 * closed with an `InvalidArgumentException` naming the key; the package checks
 * them when it boots and `mfa:check` reports them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeSettings
{
    /** @var string The placeholder the SMS message must carry; the code replaces it. */
    public const string CODE_PLACEHOLDER = ':code';

    /** @var string Prefix of every code setting's key. */
    private const string PREFIX = 'mfa.codes.';

    /** @var string The SMS message when none is configured. */
    private const string SMS_MESSAGE = 'Your verification code is: ' . self::CODE_PLACEHOLDER;

    /** @var int The resend cooldown when none is configured, in seconds; its greatest is the code lifetime. */
    private const int RESEND_COOLDOWN_SECONDS = 60;

    /** @var int The challenge lifetime when none is configured, in minutes; its least is the code lifetime. */
    private const int CHALLENGE_TTL_MINUTES = 30;

    /** @var int The greatest challenge lifetime, in minutes. */
    private const int MAX_CHALLENGE_TTL_MINUTES = 60;

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each other numeric setting. */
    private const array NUMBERS = [
        'length'              => [6, 6, 10],
        'ttl_minutes'         => [10, 1, 10],
        'max_attempts'        => [5, 1, 10],
        'factor_send_limit'   => [5, 1, 50],
        'identity_send_limit' => [10, 1, 100],
        'send_window_minutes' => [60, 1, 1440],
    ];

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
     * The number of digits in a code, 6 to 10.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function length(): int
    {
        return $this->number('length');
    }

    /**
     * How long a code works after it is sent, in minutes, 1 to 10.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function ttlMinutes(): int
    {
        return $this->number('ttl_minutes');
    }

    /**
     * How many codes may be checked against one challenge, 1 to 10. A resend
     * keeps the count, so a new code never brings new attempts.
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
     * How long a challenge lasts from its first code, in minutes, from the code
     * lifetime to 60: a resend sends a new code for the same challenge, which
     * never works past this.
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
     * How long after a code is sent another may be sent for the same challenge,
     * in seconds, from 0 to the code lifetime.
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
     * How many codes one factor may be sent within the send window, 1 to 50.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function factorSendLimit(): int
    {
        return $this->number('factor_send_limit');
    }

    /**
     * How many codes one identity may be sent within the send window, across
     * its factors and sessions, 1 to 100.
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
     * The window the send limits count over, in minutes, 1 to 1440.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function sendWindowMinutes(): int
    {
        return $this->number('send_window_minutes');
    }

    /**
     * The SMS message, which must carry the `:code` placeholder the code
     * replaces: without it, every message would go out without its code.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function smsMessage(): string
    {
        $message = $this->config->get(self::PREFIX . 'sms_message', self::SMS_MESSAGE);

        if (!is_string($message) || !str_contains($message, self::CODE_PLACEHOLDER)) {
            throw new \InvalidArgumentException(sprintf('%ssms_message must be a string carrying the %s placeholder.', self::PREFIX, self::CODE_PLACEHOLDER));
        }

        return $message;
    }

    /**
     * The class of the email message carrying a code: `MfaCodeMessage` or a
     * subclass of it.
     *
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
     * Read every setting, failing closed on the first that is out of bounds.
     *
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
        $this->smsMessage();
        $this->mailable();
    }

    /**
     * Read a numeric setting from its least to its greatest value.
     *
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
