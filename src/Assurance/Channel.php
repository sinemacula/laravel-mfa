<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * Where a factor's or a first factor's proof travels or lives: its kind and,
 * where it has one, its destination (an E.164 phone number or an email address)
 * or credential (a factor, a passkey credential or a provider).
 *
 * Two proofs on the same channel are not independent. A first factor whose
 * channel is unknown establishes no independence and no level.
 *
 * The reference may be a full destination, so it is held as a
 * `\SensitiveParameterValue` and read through `reference()`: no dump of a
 * channel (`print_r`, `var_dump`, `var_export`, an array cast, or Symfony's
 * VarDumper behind Laravel's dump helpers) shows it, and PHP refuses to
 * serialise one. The serialised form, `toArray()`, is for storing a proof,
 * never for an event, a log or a response: those carry a factor's masked
 * summary.
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
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  ?string  $reference
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The kind of channel. */
        public ChannelKind $kind,

        // The destination or credential the channel names, if any.
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
     * The channel of a first factor that is not known, or not supplied by a
     * trusted source.
     *
     * @return self
     */
    public static function unknown(): self
    {
        return new self(ChannelKind::UNKNOWN);
    }

    /**
     * Read a channel back from its serialised form.
     *
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
     * The destination or credential the channel names, or `null` when it names
     * none.
     *
     * @return ?string
     */
    public function reference(): ?string
    {
        /** @var ?string */
        return $this->reference->getValue();
    }

    /**
     * The channel with snake_case keys.
     *
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
     * The channel as JSON serialises it: the same as `toArray()`.
     *
     * @return array{kind: string, reference: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
