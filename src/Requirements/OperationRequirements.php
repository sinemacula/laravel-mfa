<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Enums\Operation;

/**
 * The requirement a named operation's step-up must meet on an application: the
 * one the application's `freshness` block configures for it (see
 * `ApplicationSettings::freshness()`), made stricter by a caller's own.
 *
 * Either applies alone when the other is absent, and with neither there is no
 * requirement, so the operation is never fresh. A name that is not in the form
 * an operation's takes has no requirement whatever the caller asks. A caller's
 * requirement that asks for nothing adds nothing; one with a part that carries
 * no maximum age, or one longer than a day, is a programming error and refused.
 *
 * Stateless: the configuration is read on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OperationRequirements
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the requirements are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The requirement the operation's step-up must meet on the application: the
     * strictest of the configured one and the caller's, either alone when the
     * other is absent, and `null` with neither or for a name that is not an
     * operation's. The caller's requirement is checked before anything else.
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
        $caller = self::callerRequirement($caller);

        if (!Operation::isName($operation)) {
            return null;
        }

        $configured = (new ApplicationSettings($this->config, $application))->freshnessFor($operation);

        return match (true) {
            $configured === null => $caller,
            $caller     === null => $configured,
            default              => Requirement::strictest($configured, $caller),
        };
    }

    /**
     * The caller's requirement, `null` when it asks for nothing, refusing one
     * with a part that carries no maximum age or one longer than a day.
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
