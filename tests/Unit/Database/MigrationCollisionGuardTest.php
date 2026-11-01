<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Builder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Mfa\Exceptions\TableAlreadyExistsException;

/**
 * Unit tests for the `MigrationCollisionGuard`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
final class MigrationCollisionGuardTest extends TestCase
{
    /**
     * Test ensure not exists no-ops when the table does not exist.
     *
     * @return void
     */
    public function testEnsureNotExistsNoOpsWhenTableDoesNotExist(): void
    {
        $schema = $this->createMock(Builder::class);
        $schema->method('hasTable')->with('mfa_factors')->willReturn(false);

        $guard = new MigrationCollisionGuard($schema);

        // Capture the public outcome as a tagged sentinel: the closure returns
        // it only when the guard returns normally, so the assertion below
        // proves the no-op rather than relying on implicit teardown semantics.
        $outcome = (static function () use ($guard): string {

            $guard->ensureNotExists('mfa_factors', 'factor.table');

            return 'no-op';
        })();

        self::assertSame('no-op', $outcome);
    }

    /**
     * Test ensure not exists throws when table exists.
     *
     * @return void
     */
    public function testEnsureNotExistsThrowsWhenTableExists(): void
    {
        $connection = self::createStub(Connection::class);
        $connection->method('getName')->willReturn('primary');

        $schema = $this->createMock(Builder::class);
        $schema->method('hasTable')->with('mfa_factors')->willReturn(true);
        $schema->method('getConnection')->willReturn($connection);

        $guard = new MigrationCollisionGuard($schema);

        try {
            $guard->ensureNotExists('mfa_factors', 'factor.table');
            self::fail('Expected TableAlreadyExistsException to be thrown.');
        } catch (TableAlreadyExistsException $exception) {
            self::assertSame(
                'Cannot install the laravel-mfa migrations: a table named \'mfa_factors\' already exists on connection'
                . ' \'primary\'. Set `factor.table` in config/mfa.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }
    }

    /**
     * Test exception message falls back to default connection name.
     *
     * @return void
     */
    public function testExceptionMessageFallsBackToDefaultConnectionName(): void
    {
        $connection = self::createStub(Connection::class);
        $connection->method('getName')->willReturn(null);

        $schema = $this->createMock(Builder::class);
        $schema->method('hasTable')->with('legacy_factors')->willReturn(true);
        $schema->method('getConnection')->willReturn($connection);

        $guard = new MigrationCollisionGuard($schema);

        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage('\'default\'');

        $guard->ensureNotExists('legacy_factors', 'factor.table');
    }
}
