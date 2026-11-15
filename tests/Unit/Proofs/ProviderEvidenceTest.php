<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Proofs\ProviderEvidence;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProviderEvidence::class)]
final class ProviderEvidenceTest extends TestCase
{
    /**
     * @return void
     */
    public function testItKeepsWhatTheProviderReported(): void
    {
        $evidence = new ProviderEvidence(['mfa', 'pwd'], 'urn:example:acr:2');

        self::assertSame(['methods' => ['mfa', 'pwd'], 'context' => 'urn:example:acr:2'], $evidence->toArray());
        self::assertSame($evidence->toArray(), $evidence->jsonSerialize());
        self::assertSame($evidence->toArray(), ProviderEvidence::fromArray($evidence->toArray())->toArray());
        self::assertSame(['methods' => [], 'context' => 'urn:example:acr:1'], (new ProviderEvidence([], 'urn:example:acr:1'))->toArray());
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, ?string, string}>
     */
    public static function refused(): iterable
    {
        yield 'methods not a list' => [['a' => 'pwd'], null, 'methods must be a list'];
        yield 'a method not a string' => [[1], null, 'methods must be a list'];
        yield 'a blank method' => [[' '], null, 'methods must be a list'];
        yield 'a repeated method' => [['pwd', 'pwd'], null, 'methods must be a list'];
        yield 'a blank context' => [['pwd'], ' ', 'context must not be blank'];
    }

    /**
     * @param  array<array-key, mixed>  $methods
     * @param  ?string  $context
     * @param  string  $message
     * @return void
     */
    #[DataProvider('refused')]
    public function testMalformedEvidenceIsRefused(array $methods, ?string $context, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new ProviderEvidence($methods, $context);
    }

    /**
     * @return void
     */
    public function testAnUnknownFieldIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        ProviderEvidence::fromArray(['methods' => [], 'context' => null, 'level' => 'aal2']);
    }
}
