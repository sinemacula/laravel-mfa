<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

/**
 * A value whose JSON and string forms throw, as another package's secret does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefusesToBeLogged implements \JsonSerializable, \Stringable
{
    /** @var string */
    public const string VALUE = '582014';

    /**
     * @param  string  $value
     */
    public function __construct(

        /** Never given up. */
        public string $value = self::VALUE,
    ) {}

    /**
     * @return string
     *
     * @throws \LogicException
     */
    #[\Override]
    public function __toString(): string
    {
        throw new \LogicException('This value cannot be cast to a string.');
    }

    /**
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function jsonSerialize(): never
    {
        throw new \LogicException('This value cannot be serialised.');
    }
}
