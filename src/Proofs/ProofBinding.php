<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * What a proof is bound to; it counts only for its own identity, application,
 * session and purpose.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, string>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProofBinding implements \JsonSerializable, Arrayable
{
    /**
     * @param  string  $identityType
     * @param  string  $identityKey
     * @param  string  $application
     * @param  string  $sessionId
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Such as the identity's morph class. */
        public string $identityType,

        /** The identity's key, as a string. */
        public string $identityKey,

        /** The application the proof was made on. */
        public string $application,

        /** The pending or active session the proof was made in. */
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
     * @param  array<array-key, mixed>  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        $fields = new SerializedFields($data, 'a serialised proof binding');

        $fields->refuseUnknown('identity_type', 'identity_key', 'application', 'session_id', 'purpose');

        return new self(
            $fields->string('identity_type'),
            $fields->string('identity_key'),
            $fields->string('application'),
            $fields->string('session_id'),
            $fields->enum('purpose', Purpose::class),
        );
    }

    /**
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
     * @return array{identity_type: string, identity_key: string, application: string, session_id: string, purpose: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
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
