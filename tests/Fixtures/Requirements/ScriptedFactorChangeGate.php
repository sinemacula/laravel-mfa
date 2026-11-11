<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;

/**
 * Records every request with its transaction level, then refuses with the given
 * refusal or allows until the given instant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedFactorChangeGate implements FactorChangeGate
{
    /** @var list<\SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest> Oldest first. */
    public array $requests = [];

    /** @var list<int> The storage connection's transaction level per request. */
    public array $levels = [];

    /**
     * @param  ?\Carbon\CarbonImmutable  $until
     * @param  ?\Throwable  $refusal
     */
    public function __construct(

        /** When the authorisation ends. */
        private readonly ?CarbonImmutable $until = null,

        /** Thrown instead of allowing. */
        private readonly ?\Throwable $refusal = null,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \Throwable
     */
    #[\Override]
    public function authorize(FactorChangeRequest $request): ?CarbonImmutable
    {
        $this->requests[] = $request;
        $this->levels[]   = DB::connection(StorageConnection::name())->transactionLevel();

        if ($this->refusal !== null) {
            throw $this->refusal;
        }

        return $this->until;
    }
}
