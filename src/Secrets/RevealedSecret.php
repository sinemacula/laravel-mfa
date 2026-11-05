<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException;

/**
 * A secret the package returns once, for the response that shows it: a TOTP
 * secret or provisioning URI when an enrolment starts, or a recovery code when
 * a set is generated. The package keeps no plaintext of it afterwards, so it
 * cannot be shown again. A delivered code reaches its sender as one too, in a
 * `Codes\CodeMessage`, revealed only into the message to its recipient.
 *
 * The plaintext is held as a `\SensitiveParameterValue` and leaves the value
 * only through `reveal()`. Casting it to a string, encoding it as JSON,
 * serialising it (into a session, a cache or a queued job) and unserialising
 * one all throw a `SecretNotRevealedException`, and no dump of it (`print_r`,
 * `var_dump`, `var_export`, or Symfony's VarDumper behind Laravel's dump
 * helpers) shows the plaintext. Send it with `SecretResponse::json()`, which
 * reveals every secret in the body and sends the response with
 * `Cache-Control: no-store`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevealedSecret implements \JsonSerializable, \Stringable
{
    /** @var string What a dump shows in place of the plaintext. */
    public const string REDACTED = '[redacted]';

    /** @var \SensitiveParameterValue The plaintext, hidden from dumps. */
    private \SensitiveParameterValue $value;

    /**
     * Constructor.
     *
     * @param  string  $value
     */
    public function __construct(#[\SensitiveParameter] string $value)
    {
        $this->value = new \SensitiveParameterValue($value);
    }

    /**
     * Refuse to become a string, so the secret never reaches a log line, a
     * message or a view by interpolation.
     *
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException
     */
    #[\Override]
    public function __toString(): string
    {
        throw new SecretNotRevealedException('A secret cannot be cast to a string: call reveal() where it is shown.');
    }

    /**
     * Refuse to be serialised, so the secret is never kept in a session, a
     * cache or a queued job.
     *
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException
     */
    public function __serialize(): array
    {
        throw new SecretNotRevealedException('A secret cannot be serialised.');
    }

    /**
     * Refuse to be unserialised, so no secret is rebuilt from a stored payload.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException
     */
    public function __unserialize(array $data): void
    {
        throw new SecretNotRevealedException('A secret cannot be unserialised.');
    }

    /**
     * What a dump shows: a marker in place of the plaintext.
     *
     * @return array{secret: string}
     */
    public function __debugInfo(): array
    {
        return ['secret' => self::REDACTED];
    }

    /**
     * The plaintext, for the one response that shows it.
     *
     * @return string
     */
    public function reveal(): string
    {
        /** @var string */
        return $this->value->getValue();
    }

    /**
     * Refuse to be encoded as JSON, so the secret never reaches a body that is
     * not sent with `Cache-Control: no-store`.
     *
     * @return mixed
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException
     */
    #[\Override]
    public function jsonSerialize(): mixed
    {
        throw new SecretNotRevealedException('A secret cannot be encoded as JSON: send it with SecretResponse::json().');
    }
}
