<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\TableNames;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TableNames::class)]
final class TableNamesTest extends TestCase
{
    /**
     * A renamed table fails here.
     *
     * @return void
     */
    public function testTheTablesAreTheStableNames(): void
    {
        self::assertSame([
            'factor'         => 'mfa_factors',
            'identity_state' => 'mfa_identity_states',
            'enrollment'     => 'mfa_enrollments',
            'codes'          => 'mfa_codes',
            'recovery_codes' => 'mfa_recovery_codes',
            'attempts'       => 'mfa_attempts',
            'passkeys'       => 'mfa_passkey_associations',
        ], TableNames::DEFAULTS);
    }

    /**
     * @return void
     */
    public function testATablesSettingIsInItsBlock(): void
    {
        self::assertSame('mfa.codes.table', TableNames::setting(TableNames::CODES));
    }

    /**
     * @return void
     */
    public function testTheConfiguredNameWinsOverTheDefault(): void
    {
        Config::set('mfa.codes.table', 'delivered_codes');
        self::assertSame('delivered_codes', TableNames::of(TableNames::CODES));

        Config::set('mfa.codes.table', ' ');
        self::assertSame('mfa_codes', TableNames::of(TableNames::CODES));

        Config::set('mfa.codes.table', ['delivered_codes']);
        self::assertSame('mfa_codes', TableNames::of(TableNames::CODES));

        Config::set('mfa.codes.table', null);
        self::assertSame('mfa_codes', TableNames::of(TableNames::CODES));
    }

    /**
     * @return void
     */
    public function testBeforeTheConfigurationTheDefaultIsRead(): void
    {
        Config::set('mfa.codes.table', 'delivered_codes');

        $previous = Facade::getFacadeApplication();

        // @phpstan-ignore argument.type
        Facade::setFacadeApplication(null);
        Facade::clearResolvedInstance('config');

        try {
            self::assertSame('mfa_codes', TableNames::of(TableNames::CODES));
        } finally {
            Facade::setFacadeApplication($previous);
        }
    }

    /**
     * @return void
     */
    public function testABlockWithoutATableIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The package creates no table for [totp].');

        TableNames::of('totp');
    }
}
