<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Enums\Operation;

/**
 * The requirement a named operation's step-up must meet: the application's
 * `freshness` setting, made stricter by a caller's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OperationRequirements
{
    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call. */
        private Repository $config,
    ) {}

    /**
     * The stricter of the configured and caller's requirement, either alone, or
     * `null` with neither or for a name that is not an operation's.
     *
     * @param  string  $application
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $caller
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    public function effective(string $application, string $operation, ?Requirement $caller = null): ?Requirement
    {
        if (!Operation::isName($operation)) {
            return null;
        }

        $caller = self::callerRequirement($caller);

        $configured = (new ApplicationSettings($this->config, $application))->freshnessFor($operation);

        return match (true) {
            $configured === null => $caller,
            $caller     === null => $configured,
            default              => Requirement::strictest($configured, $caller),
        };
    }

    /**
     * `null` for a requirement that asks for nothing; one without a bounded
     * maximum age is refused.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    private static function callerRequirement(?Requirement $requirement): ?Requirement
    {
        if ($requirement === null || $requirement->isEmpty()) {
            return null;
        }

        return FreshnessBounds::assertBounded($requirement, 'A caller\'s requirement');
    }
}
