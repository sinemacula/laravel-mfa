<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Assurance\Authenticator;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * One verified authentication event. The serialised form holds the full
 * destination, so it is for storage, never events, logs or responses.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, mixed>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Proof implements \JsonSerializable, Arrayable
{
    /** @var string ISO-8601 to the microsecond, with offset. */
    private const string TIME_FORMAT = 'Y-m-d\TH:i:s.uP';

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\ProofKind  $kind
     * @param  string  $method
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  ?string  $reference
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  \Carbon\CarbonImmutable  $provedAt
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  int  $generation
     * @param  ?string  $challengeId
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The kind of proof. */
        public ProofKind $kind,

        /** The method proved, such as `password`, `totp`, `sms` or `passkey`. */
        public string $method,

        /** The channel the proof travelled on, or `null` for a recovery code. */
        public ?Channel $channel,

        /** The factor or credential the proof was made with, when it names one. */
        public ?string $reference,

        /** What the proof actually observed. */
        public ObservedProperties $properties,

        /** When the proof was made. */
        public CarbonImmutable $provedAt,

        /** What the proof is bound to. */
        public ProofBinding $binding,

        /** The identity's verification generation when the proof was made. */
        public int $generation,

        /** The challenge the proof answered, when one was used. */
        public ?string $challengeId = null,
    ) {
        if (trim($method) === '') {
            throw new \InvalidArgumentException('The method of a proof must not be blank.');
        }

        $this->assertChannel();
        $this->assertReference();
        $this->assertPurpose();

        if ($generation < 0) {
            throw new \InvalidArgumentException('The verification generation of a proof must not be negative.');
        }

        if ($challengeId !== null && trim($challengeId) === '') {
            throw new \InvalidArgumentException('The challenge id of a proof must not be blank.');
        }
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        $fields = new SerializedFields($data, 'a serialised proof');

        $fields->refuseUnknown('kind', 'method', 'channel', 'reference', 'properties', 'proved_at', 'binding', 'generation', 'challenge_id');

        $channel = $fields->nullableArray('channel');

        return new self(
            $fields->enum('kind', ProofKind::class),
            $fields->string('method'),
            $channel === null ? null : Channel::fromArray($channel),
            $fields->nullableString('reference'),
            ObservedProperties::fromArray($fields->array('properties')),
            self::readTime($fields->string('proved_at')),
            ProofBinding::fromArray($fields->array('binding')),
            $fields->int('generation'),
            $fields->nullableString('challenge_id'),
        );
    }

    /**
     * The RFC 8176 `amr` values the proof adds, from its channel and observed
     * properties.
     *
     * @return list<string>
     */
    public function amr(): array
    {
        return Authenticator::of($this)->amr;
    }

    /**
     * @param  int  $generation
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withGeneration(int $generation): self
    {
        return new self($this->kind, $this->method, $this->channel, $this->reference, $this->properties, $this->provedAt, $this->binding, $generation, $this->challengeId);
    }

    /**
     * @return array<string, mixed>
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'kind'         => $this->kind->value,
            'method'       => $this->method,
            'channel'      => $this->channel?->toArray(),
            'reference'    => $this->reference,
            'properties'   => $this->properties->toArray(),
            'proved_at'    => $this->provedAt->format(self::TIME_FORMAT),
            'binding'      => $this->binding->toArray(),
            'generation'   => $this->generation,
            'challenge_id' => $this->challengeId,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Refuse a time that only parses by overflowing.
     *
     * @param  string  $value
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private static function readTime(string $value): CarbonImmutable
    {
        $time = \DateTimeImmutable::createFromFormat(self::TIME_FORMAT, $value);

        if ($time === false || $time->format(self::TIME_FORMAT) !== $value) {
            throw new \InvalidArgumentException('The [proved_at] field of a serialised proof is not a time in the serialised format.');
        }

        return CarbonImmutable::instance($time);
    }

    /**
     * An additional factor never travels on a password or unknown channel.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertChannel(): void
    {
        if ($this->kind->hasChannel() && $this->channel === null) {
            throw new \InvalidArgumentException(sprintf('A proof of kind [%s] needs a channel.', $this->kind->value));
        }

        if (!$this->kind->hasChannel() && $this->channel !== null) {
            throw new \InvalidArgumentException(sprintf('A proof of kind [%s] has no channel.', $this->kind->value));
        }

        $channel = $this->channel;

        if ($this->kind === ProofKind::ADDITIONAL_FACTOR && $channel !== null && !$channel->kind->carriesFactor()) {
            throw new \InvalidArgumentException(sprintf('An additional factor proof cannot travel on a channel of kind [%s].', $channel->kind->value));
        }
    }

    /**
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertReference(): void
    {
        if ($this->reference !== null && trim($this->reference) === '') {
            throw new \InvalidArgumentException('The factor or credential reference of a proof must not be blank.');
        }

        if ($this->kind === ProofKind::ADDITIONAL_FACTOR && $this->reference === null) {
            throw new \InvalidArgumentException('An additional factor proof needs the reference of the factor it was made with.');
        }
    }

    /**
     * A recovery code cannot confirm an enrolment.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertPurpose(): void
    {
        $required = $this->kind->requiredPurpose();

        $purpose = $this->binding->purpose;

        if ($required !== null && $required !== $purpose) {
            throw new \InvalidArgumentException(sprintf('A proof of kind [%s] carries the [%s] purpose, not [%s].', $this->kind->value, $required->value, $purpose->value));
        }

        if ($this->kind === ProofKind::RECOVERY_CODE && $purpose === Purpose::ENROLLMENT) {
            throw new \InvalidArgumentException('A recovery code proof cannot confirm an enrolment.');
        }
    }
}
