<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

/**
 * The bounds of a requirement a step-up is checked against: every part it asks
 * for carries a maximum age, of at most a day. An operation's configured
 * requirement and a caller's requirement are both held to them, so whatever
 * judges the step-up, the package's own gate or one an authentication layer's
 * adapter binds, is always given a bounded age to judge.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FreshnessBounds
{
    /** @var int The longest maximum age a step-up's requirement may give a part, in seconds. */
    public const int MOST_SECONDS = 86400;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Return the requirement, refusing one with a part that carries no maximum
     * age or one longer than a day. A requirement's maximum ages are at least a
     * second already.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  string  $subject
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    public static function assertBounded(Requirement $requirement, string $subject): Requirement
    {
        foreach ($requirement->parts() as $part) {

            $maxAge = $requirement->maxAge($part);

            if ($maxAge === null || $maxAge > self::MOST_SECONDS) {
                $message = '%s must give every part a max_age from 1 to %d seconds, which its [%s] part does not.';

                throw new \InvalidArgumentException(sprintf($message, $subject, self::MOST_SECONDS, $part->value));
            }
        }

        return $requirement;
    }
}
