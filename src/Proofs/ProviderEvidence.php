<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * What an external provider reported about a sign-in, as it reported it. The
 * package never judges it; a rebound combination policy may.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, list<string>|string|null>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class ProviderEvidence implements \JsonSerializable, Arrayable
{
    /** @var list<string> The methods the provider reported (RFC 8176 `amr`), in its order and spelling. */
    public array $methods;

    /**
     * @param  array<array-key, mixed>  $methods
     * @param  ?string  $context
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        // The methods as reported, checked before they are kept.
        array $methods,

        /** The context the provider reported (`acr` or `AuthnContextClassRef`), raw. */
        public ?string $context = null,
    ) {
        $this->methods = self::methodsOf($methods);

        if ($context !== null && trim($context) === '') {
            throw new \InvalidArgumentException('A provider\'s context must not be blank.');
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
        $fields = new SerializedFields($data, 'a provider\'s evidence');

        $fields->refuseUnknown('methods', 'context');

        return new self($fields->array('methods'), $fields->nullableString('context'));
    }

    /**
     * @return array{methods: list<string>, context: ?string}
     */
    #[\Override]
    public function toArray(): array
    {
        return ['methods' => $this->methods, 'context' => $this->context];
    }

    /**
     * @return array{methods: list<string>, context: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * @param  array<array-key, mixed>  $methods
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private static function methodsOf(array $methods): array
    {
        $kept = array_values(array_filter($methods, static fn (mixed $method): bool => is_string($method) && trim($method) !== ''));

        if (!array_is_list($methods) || $kept !== $methods || count(array_unique($kept)) !== count($kept)) {
            throw new \InvalidArgumentException('A provider\'s methods must be a list of distinct, non-blank strings.');
        }

        return $kept;
    }
}
