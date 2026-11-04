<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;

/**
 * A factor change gate as an authentication layer's adapter might bind it: it
 * records every request with the transaction level it was asked at, then
 * refuses with the refusal given, or allows until the instant given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedFactorChangeGate implements FactorChangeGate
{
    /** @var list<\SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest> The requests asked, oldest first. */
    public array $requests = [];

    /** @var list<int> The storage connection's transaction level at each request. */
    public array $levels = [];

    /**
     * Constructor.
     *
     * @param  ?\Carbon\CarbonImmutable  $until
     * @param  ?\Throwable  $refusal
     */
    public function __construct(

        /** When the authorisation ends, if it is given. */
        private readonly ?CarbonImmutable $until = null,

        /** What it throws instead of allowing, if anything. */
        private readonly ?\Throwable $refusal = null,
    ) {}

    /**
     * Record the request, then refuse or allow.
     *
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
