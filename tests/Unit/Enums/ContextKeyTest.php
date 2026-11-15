<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor;
use SineMacula\Laravel\Mfa\Enums\ContextKey;
use SineMacula\Laravel\Mfa\Enums\ContextValueType;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextKey::class)]
#[CoversClass(ContextValueType::class)]
final class ContextKeyTest extends TestCase
{
    /**
     * @return void
     */
    public function testTheKeysAreTheContributorsUnderItsNamespace(): void
    {
        $keys = array_map(static fn (string $key): string => AuthenticationContextContributor::NAMESPACE . '.' . $key, array_keys(AuthenticationContextContributor::neutral()));

        self::assertSame($keys, array_column(ContextKey::cases(), 'value'));
    }

    /**
     * @return void
     */
    public function testEachKeyHasItsType(): void
    {
        self::assertSame([
            'mfa.accepted'                      => 'bool',
            'mfa.multifactor'                   => 'bool',
            'mfa.factor_types'                  => 'list',
            'mfa.level'                         => 'string',
            'mfa.phishing_resistant'            => 'bool',
            'mfa.user_verification'             => 'bool',
            'mfa.last_verification_age_seconds' => 'number',
            'mfa.has_confirmed_factor'          => 'bool',
        ], array_combine(
            array_column(ContextKey::cases(), 'value'),
            array_map(static fn (ContextKey $key): string => $key->type()->value, ContextKey::cases()),
        ));
    }
}
