<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Illuminate\Config\Repository;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Lifecycle\Concerns\HoldsIdentityRecords;
use Tests\TestCase;

/**
 * Without the test transaction, so the forgetting opens its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HasFactors::class)]
final class HasFactorsStandaloneDeleteTest extends TestCase
{
    use HoldsIdentityRecords;

    /**
     * Codes and enrolments are forgotten before the missing table fails it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedForgettingKeepsTheRecordsButNotTheIdentity(): void
    {
        $identity = FactorHolder::query()->create(['email' => 'one@example.test']);

        $this->giveRecords($identity);

        $setting = TableNames::setting(TableNames::PASSKEY_ASSOCIATIONS);
        $config  = $this->container()->make(Repository::class);

        $config->set($setting, 'missing_passkey_associations');

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());

        try {
            $identity->delete();
            self::fail('The forgetting was expected to fail.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(QueryException::class, $exception);
        }

        $config->set($setting, null);

        self::assertFalse(FactorHolder::query()->whereKey($identity->id)->exists());
        self::assertSame($this->eachTableHolding(1), $this->recordCounts($identity));
    }
}
