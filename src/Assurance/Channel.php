<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * Where a proof travels or lives. Two proofs on the same channel are not
 * independent, and an unknown first-factor channel establishes no level.
 *
 * The reference may be a full destination, so it is hidden from dumps and
 * serialisation; `toArray()` is for storing a proof, never for events, logs or
 * responses.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, ?string>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Channel implements \JsonSerializable, Arrayable
{
    /** @var \SensitiveParameterValue The destination or credential the channel names, hidden from dumps. */
    private \SensitiveParameterValue $reference;

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  ?string  $reference
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The channel kind. */
        public ChannelKind $kind,

        // An E.164 number, email address, or factor, credential or provider id.
        #[\SensitiveParameter]
        ?string $reference = null,
    ) {
        $this->reference = new \SensitiveParameterValue($reference);

        if ($reference === null) {
            return;
        }

        if (trim($reference) === '') {
            throw new \InvalidArgumentException('A channel reference must not be blank.');
        }

        if (!$kind->takesReference()) {
            throw new \InvalidArgumentException(sprintf('A channel of kind [%s] takes no reference.', $kind->value));
        }
    }

    /**
     * A first-factor channel that is not known or not from a trusted source.
     *
     * @return self
     */
    public static function unknown(): self
    {
        return new self(ChannelKind::UNKNOWN);
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        $fields = new SerializedFields($data, 'a serialised channel');

        $fields->refuseUnknown('kind', 'reference');

        return new self($fields->enum('kind', ChannelKind::class), $fields->nullableString('reference'));
    }

    /**
     * @return ?string
     */
    public function reference(): ?string
    {
        /** @var ?string */
        return $this->reference->getValue();
    }

    /**
     * @return array{kind: string, reference: ?string}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'kind'      => $this->kind->value,
            'reference' => $this->reference(),
        ];
    }

    /**
     * @return array{kind: string, reference: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
