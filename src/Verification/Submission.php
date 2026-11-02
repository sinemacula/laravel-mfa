<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use SineMacula\Laravel\Mfa\Enums\SubmissionKind;

/**
 * What a person submits to verify: a code for one of their factors, a code
 * answering a challenge sent to a delivered factor, a recovery code, or a
 * passkey's response to an assertion request.
 *
 * It holds a secret, so nothing but its own properties ever shows it: dumping
 * it or encoding it as JSON leaves out the code and the response, and
 * serialising it is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class Submission implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\SubmissionKind  $kind
     * @param  mixed  $factorId
     * @param  ?string  $challengeId
     * @param  ?string  $code
     * @param  array<string, mixed>  $response
     */
    private function __construct(

        /** What is submitted. */
        public SubmissionKind $kind,

        /** The factor named, or `null` for a recovery code. */
        public mixed $factorId = null,

        /** The challenge answered, for a delivered factor. */
        public ?string $challengeId = null,

        /** The code, in clear, for anything but an assertion. */
        #[\SensitiveParameter]
        public ?string $code = null,

        /** The client's response to an assertion request. */
        #[\SensitiveParameter]
        public array $response = [],
    ) {}

    /**
     * What a dump shows: never the code or the response.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    /**
     * Refuse to serialise the secret.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     */
    public function __serialize(): array
    {
        throw new \LogicException('A submission holds a secret, so it is never serialised.');
    }

    /**
     * Refuse to read a submission back.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A submission holds a secret, so it is never serialised.');
    }

    /**
     * A code for a factor that makes its own, such as TOTP.
     *
     * @param  mixed  $factorId
     * @param  string  $code
     * @return self
     */
    public static function factor(mixed $factorId, #[\SensitiveParameter] string $code): self
    {
        return new self(SubmissionKind::FACTOR, $factorId, code: $code);
    }

    /**
     * A code answering the challenge sent to a delivered factor.
     *
     * @param  mixed  $factorId
     * @param  string  $challengeId
     * @param  string  $code
     * @return self
     */
    public static function challenge(mixed $factorId, string $challengeId, #[\SensitiveParameter] string $code): self
    {
        return new self(SubmissionKind::CHALLENGE, $factorId, $challengeId, $code);
    }

    /**
     * A recovery code.
     *
     * @param  string  $code
     * @return self
     */
    public static function recoveryCode(#[\SensitiveParameter] string $code): self
    {
        return new self(SubmissionKind::RECOVERY_CODE, code: $code);
    }

    /**
     * A passkey's response to an assertion request.
     *
     * @param  mixed  $factorId
     * @param  array<string, mixed>  $response
     * @return self
     */
    public static function assertion(mixed $factorId, #[\SensitiveParameter] array $response): self
    {
        return new self(SubmissionKind::ASSERTION, $factorId, response: $response);
    }

    /**
     * What JSON shows: never the code or the response.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'kind'         => $this->kind->value,
            'factor_id'    => $this->factorId,
            'challenge_id' => $this->challengeId,
        ];
    }
}
