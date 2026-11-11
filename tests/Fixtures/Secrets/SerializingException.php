<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

/**
 * An exception whose JSON form, which Monolog logs in its place, holds a code
 * or throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SerializingException extends \RuntimeException implements \JsonSerializable
{
    /** @var string */
    public const string CODE = '604183';

    /**
     * @param  bool  $refuses
     */
    public function __construct(

        /** Whether its JSON form throws instead of giving the code. */
        private readonly bool $refuses = false,
    ) {
        parent::__construct('Delivery failed.');
    }

    /**
     * @return array<string, string>
     *
     * @throws \LogicException
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        if ($this->refuses) {
            throw new \LogicException('This exception cannot be serialised.');
        }

        return ['code' => self::CODE, 'label' => 'Phone'];
    }
}
