<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * What a proof is bound to: the identity (its type and key), the application,
 * the session it was made in and the purpose it was made for. A proof counts
 * only for its own binding, so one made for another identity, application,
 * session or purpose satisfies nothing.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, string>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProofBinding implements \JsonSerializable, Arrayable
{
    /**
     * Constructor.
     *
     * @param  string  $identityType
     * @param  string  $identityKey
     * @param  string  $application
     * @param  string  $sessionId
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity's type, such as its morph class. */
        public string $identityType,

        /** The identity's key, as a string. */
        public string $identityKey,

        /** The application the proof was made on. */
        public string $application,

        /** The session, pending or active, the proof was made in. */
        public string $sessionId,

        /** What the proof was made for. */
        public Purpose $purpose,
    ) {
        self::assertNotBlank($identityType, 'identity type');
        self::assertNotBlank($identityKey, 'identity key');
        self::assertNotBlank($application, 'application');
        self::assertNotBlank($sessionId, 'session id');
    }

    /**
     * Read a binding back from its serialised form.
     *
     * @param  array<array-key, mixed>  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        $fields = new SerializedFields($data, 'a serialised proof binding');

        return new self(
            $fields->string('identity_type'),
            $fields->string('identity_key'),
            $fields->string('application'),
            $fields->string('session_id'),
            $fields->enum('purpose', Purpose::class),
        );
    }

    /**
     * The binding with snake_case keys.
     *
     * @return array{identity_type: string, identity_key: string, application: string, session_id: string, purpose: string}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'identity_type' => $this->identityType,
            'identity_key'  => $this->identityKey,
            'application'   => $this->application,
            'session_id'    => $this->sessionId,
            'purpose'       => $this->purpose->value,
        ];
    }

    /**
     * The binding as JSON serialises it: the same as `toArray()`.
     *
     * @return array{identity_type: string, identity_key: string, application: string, session_id: string, purpose: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Refuse a blank part of the binding.
     *
     * @param  string  $value
     * @param  string  $part
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertNotBlank(string $value, string $part): void
    {
        if (trim($value) === '') {
            throw new \InvalidArgumentException(sprintf('The %s of a proof binding must not be blank.', $part));
        }
    }
}
