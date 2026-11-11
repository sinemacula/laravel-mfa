<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Passkeys\CredentialId;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CredentialId::class)]
final class CredentialIdTest extends TestCase
{
    /**
     * @return void
     */
    public function testACanonicalIdIsKept(): void
    {
        self::assertSame('Y3JlZGVudGlhbC1vbmU', CredentialId::canonical('Y3JlZGVudGlhbC1vbmU'));
        self::assertSame('_-8', CredentialId::canonical('_-8'));
        self::assertTrue(CredentialId::isCanonical('Y3JlZGVudGlhbC1vbmU'));
    }

    /**
     * @return void
     */
    public function testEncodesAndHashesTheCanonicalForm(): void
    {
        self::assertSame('Y3JlZGVudGlhbC1vbmU', CredentialId::encode('credential-one'));
        self::assertSame('_-8', CredentialId::encode("\xFF\xEF"));
        self::assertSame(hash('sha256', 'Y3JlZGVudGlhbC1vbmU'), CredentialId::hash('Y3JlZGVudGlhbC1vbmU'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function nonCanonical(): iterable
    {
        yield 'empty' => [''];
        yield 'padded' => ['Y3JlZGVudGlhbC1vbmU='];
        yield 'the standard alphabet' => ['/+8'];
        yield 'stray bits in the last character' => ['Y3JlZGVudGlhbC1vbmV'];
        yield 'an impossible length' => ['Y3JlZ'];
        yield 'whitespace' => ['Y3JlZGVudGlhbC1vbmU '];
        yield 'more than 1023 bytes' => [CredentialId::encode(str_repeat('a', 1024))];
    }

    /**
     * @param  string  $credentialId
     * @return void
     */
    #[DataProvider('nonCanonical')]
    public function testAnotherEncodingIsRefused(string $credentialId): void
    {
        self::assertFalse(CredentialId::isCanonical($credentialId));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A credential id must be the canonical unpadded base64url encoding of 1 to 1023 bytes.');

        CredentialId::canonical($credentialId);
    }

    /**
     * @return void
     */
    public function testTheLongestIdIsCanonical(): void
    {
        self::assertTrue(CredentialId::isCanonical(CredentialId::encode(str_repeat('a', 1023))));
    }

    /**
     * Its two characters decode only with no padding or with all of it.
     *
     * @return void
     */
    public function testTheShortestIdIsCanonical(): void
    {
        self::assertSame('YQ', CredentialId::canonical('YQ'));
        self::assertTrue(CredentialId::isCanonical('YQ'));
    }
}
