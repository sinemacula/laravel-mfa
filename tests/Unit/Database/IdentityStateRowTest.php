<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\IdentityStateRow;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityStateRow::class)]
final class IdentityStateRowTest extends TestCase
{
    /**
     * @return void
     */
    public function testMatchesTheOwnersHash(): void
    {
        $owner = new ProofOwner('users', '42');
        $query = IdentityStateRow::of($owner);

        self::assertSame('mfa_identity_states', $query->from);
        self::assertSame([$owner->hash()], $query->getBindings());
        self::assertSame(['owner_hash'], array_column($query->wheres, 'column'));
    }

    /**
     * @return void
     */
    public function testLockingCreatesTheRowOnceAndTouchesIt(): void
    {
        $owner      = new ProofOwner('users', '42');
        $connection = DB::connection();

        Carbon::setTestNow('2026-11-01 12:00:00');

        IdentityStateRow::lock($owner, $connection);

        $row = IdentityStateRow::of($owner)->sole();

        self::assertSame(['users', '42'], [$row->authenticatable_type, $row->authenticatable_id]);
        self::assertIsString($row->id);
        self::assertSame(strtolower($row->id), $row->id);
        self::assertSame('2026-11-01 12:00:00', (string) $row->created_at);
        self::assertSame('2026-11-01 12:00:00', (string) $row->updated_at);

        Carbon::setTestNow('2026-11-01 13:00:00');

        IdentityStateRow::lock($owner, $connection);
        IdentityStateRow::lock(new ProofOwner('users', '43'), $connection);

        $again = IdentityStateRow::of($owner)->sole();

        self::assertSame($row->id, $again->id);
        self::assertSame('2026-11-01 12:00:00', (string) $again->created_at);
        self::assertSame('2026-11-01 13:00:00', (string) $again->updated_at);
        self::assertSame(1, IdentityStateRow::of(new ProofOwner('users', '43'))->count());

        Carbon::setTestNow();
    }

    /**
     * @return void
     */
    public function testLockingStampsTheRowInUtc(): void
    {
        $this->useTimezone('Europe/London');

        Carbon::setTestNow(Carbon::parse('2026-07-01 12:00:00', 'UTC'));

        try {
            IdentityStateRow::lock(new ProofOwner('users', '42'), DB::connection());
        } finally {
            Carbon::setTestNow();
        }

        $row = IdentityStateRow::of(new ProofOwner('users', '42'))->sole();

        self::assertSame('2026-07-01 12:00:00', (string) $row->created_at);
        self::assertSame('2026-07-01 12:00:00', (string) $row->updated_at);
    }

    /**
     * @return void
     */
    public function testRunsOnTheStorageConnectionUnlessGivenOne(): void
    {
        config()->set('database.connections.other', config('database.connections.testing'));
        config()->set('mfa.storage.connection', 'other');

        $owner = new ProofOwner('users', '42');

        self::assertSame(DB::connection('other'), IdentityStateRow::of($owner)->getConnection());
        self::assertSame(DB::connection('testing'), IdentityStateRow::of($owner, DB::connection('testing'))->getConnection());
    }
}
