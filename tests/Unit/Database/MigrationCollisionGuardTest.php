<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Builder;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Mfa\Exceptions\FactorTableAlreadyExistsException;

/**
 * Unit tests for the `MigrationCollisionGuard`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MigrationCollisionGuardTest extends TestCase
{
    /**
     * Test ensure not exists no ops when table does not exist.
     *
     * @return void
     */
    public function testEnsureNotExistsNoOpsWhenTableDoesNotExist(): void
    {
        $schema = $this->createMock(Builder::class);
        $schema->expects(self::once())
            ->method('hasTable')
            ->with('mfa_factors')
            ->willReturn(false);
        $schema->expects(self::never())->method('getConnection');

        $guard = new MigrationCollisionGuard($schema);

        $guard->ensureNotExists('mfa_factors');

        $this->addToAssertionCount(1);
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
            $guard->ensureNotExists('mfa_factors');
            self::fail('Expected FactorTableAlreadyExistsException to be thrown.');
        } catch (FactorTableAlreadyExistsException $exception) {
            self::assertStringContainsString('mfa_factors', $exception->getMessage());
            self::assertStringContainsString('primary', $exception->getMessage());
            self::assertStringContainsString('factor.table', $exception->getMessage());
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

        $this->expectException(FactorTableAlreadyExistsException::class);
        $this->expectExceptionMessage('\'default\'');

        $guard->ensureNotExists('legacy_factors');
    }
}
