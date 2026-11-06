<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

/**
 * An exception that gives its own JSON form, which Monolog logs in place of the
 * exception: the code it holds, or, when asked to refuse, nothing but a throw.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SerializingException extends \RuntimeException implements \JsonSerializable
{
    /** @var string The code its JSON form holds. */
    public const string CODE = '604183';

    /**
     * Constructor.
     *
     * @param  bool  $refuses
     */
    public function __construct(

        /** Whether its JSON form throws rather than give the code. */
        private readonly bool $refuses = false,
    ) {
        parent::__construct('Delivery failed.');
    }

    /**
     * The JSON form, holding the code, or a throw.
     *
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
