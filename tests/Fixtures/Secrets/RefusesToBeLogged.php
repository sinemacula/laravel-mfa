<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

/**
 * A value that refuses to be logged on purpose, as another package's secret
 * does: its JSON and string forms throw rather than give what it holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefusesToBeLogged implements \JsonSerializable, \Stringable
{
    /** @var string The value it holds. */
    public const string VALUE = '582014';

    /**
     * Constructor.
     *
     * @param  string  $value
     */
    public function __construct(

        /** The value it holds, which it never gives up. */
        public string $value = self::VALUE,
    ) {}

    /**
     * Refuse to give the string form.
     *
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
     * Refuse to give the JSON form.
     *
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
