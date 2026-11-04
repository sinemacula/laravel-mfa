<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;
use Tests\Fixtures\Verification\Dumps;

/**
 * Unit tests for `RemovalRevocation`: whether the revoker judged the current
 * session itself, and what it returns, hidden from every dump.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RemovalRevocation::class)]
final class RemovalRevocationTest extends TestCase
{
    /**
     * A revoker that judged the session returns its completion; one that only
     * ended the others returns none.
     *
     * @return void
     */
    public function testSaysWhetherTheSessionWasJudgedAndWithWhat(): void
    {
        $completion = self::completion();
        $judged     = RemovalRevocation::judged($completion);

        self::assertTrue($judged->judgedCurrent);
        self::assertSame($completion, $judged->completion());
        self::assertNull(RemovalRevocation::judged()->completion());
        self::assertFalse(RemovalRevocation::othersEnded()->judgedCurrent);
        self::assertNull(RemovalRevocation::othersEnded()->completion());
    }

    /**
     * No way of dumping it shows the completion.
     *
     * @return void
     */
    public function testNoDumpShowsTheCompletion(): void
    {
        foreach (Dumps::of(RemovalRevocation::judged(self::completion())) as $way => $shown) {
            self::assertStringNotContainsString('bearer-token', $shown, $way);
        }
    }

    /**
     * A completion holding a credential.
     *
     * @return object
     */
    private static function completion(): object
    {
        return (object) ['token' => 'bearer-token'];
    }
}
