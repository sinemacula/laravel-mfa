<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets\Enums;

/**
 * An enum whose JSON form throws, as Monolog would call it for a logged case.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum RefusingCase implements \JsonSerializable
{
    case HELD;

    /**
     * @return never
     *
     * @throws \LogicException
     */
    #[\Override]
    public function jsonSerialize(): never
    {
        throw new \LogicException('This case cannot be serialised.');
    }
}
