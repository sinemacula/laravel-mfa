<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

/**
 * Holds a step-up's requirement to a maximum age of at most a day on every
 * part, so any gate judging it has a bounded age.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FreshnessBounds
{
    /** @var int Longest maximum age a part may carry, in seconds. */
    public const int MOST_SECONDS = 86400;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse a part with no maximum age or one longer than a day.
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
