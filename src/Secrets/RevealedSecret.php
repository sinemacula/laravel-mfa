<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException;

/**
 * A secret shown once, such as a TOTP secret or a recovery code; the package
 * keeps no plaintext afterwards. It leaves only through `reveal()`: string
 * casts, JSON and serialisation throw, and dumps show a marker.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevealedSecret implements \JsonSerializable, \Stringable
{
    /** @var string */
    public const string REDACTED = '[redacted]';

    /** @var \SensitiveParameterValue Hides the plaintext from dumps and traces. */
    private \SensitiveParameterValue $value;

    /**
     * @param  string  $value
     */
    public function __construct(#[\SensitiveParameter] string $value)
    {
        $this->value = new \SensitiveParameterValue($value);
    }

    /**
     * Throws so the secret never reaches a log or view by interpolation.
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
     * Throws so the secret is never kept in a session, cache or queued job.
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
     * Throws so no secret is rebuilt from a stored payload.
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
     * @return array{secret: string}
     */
    public function __debugInfo(): array
    {
        return ['secret' => self::REDACTED];
    }

    /**
     * @return string
     */
    public function reveal(): string
    {
        /** @var string */
        return $this->value->getValue();
    }

    /**
     * Throws so the secret never reaches a body sent without `no-store`.
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
