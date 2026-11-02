<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Lifecycle;

use Illuminate\Database\Eloquent\Collection;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * A last factor policy that answers from a script, one answer per ask, and runs
 * a step before it answers its first ask: it stands in for a concurrent change
 * made between the check before the lock and the check under it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedLastFactorPolicy implements LastFactorPolicy
{
    /** @var int How many times the policy was asked. */
    public int $asked = 0;

    /**
     * Constructor.
     *
     * @param  list<bool|\SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy>  $answers
     * @param  ?\Closure(): void  $beforeFirstAnswer
     */
    public function __construct(

        /** The answers, in order: a policy to ask, or the answer itself. */
        private readonly array $answers,

        /** What happens before the first answer. */
        private readonly ?\Closure $beforeFirstAnswer = null,
    ) {}

    /**
     * Run the step on the first ask, and answer from the script.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return bool
     *
     * @formatter:on
     */
    #[\Override]
    public function allowsRemoval(MultiFactorAuthenticatable $identity, string $application, Factor $factor, Collection $factors): bool
    {
        if ($this->asked === 0 && $this->beforeFirstAnswer !== null) {
            ($this->beforeFirstAnswer)();
        }

        $answer = $this->answers[$this->asked++] ?? false;

        return $answer instanceof LastFactorPolicy ? $answer->allowsRemoval($identity, $application, $factor, $factors) : $answer;
    }
}
