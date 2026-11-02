<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\SubmissionKind;
use SineMacula\Laravel\Mfa\Verification\Submission;

/**
 * Unit tests for `Submission`: each named constructor holds what its route
 * needs, and no way of showing one but its own properties shows a code or a
 * response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Submission::class)]
final class SubmissionTest extends TestCase
{
    /** @var string The secret a submission holds. */
    private const string CODE = '123456';

    /**
     * Each kind holds what its route needs, and nothing else.
     *
     * @return void
     */
    public function testEachKindHoldsWhatItsRouteNeeds(): void
    {
        $factor = Submission::factor('factor-1', self::CODE);

        self::assertSame(SubmissionKind::FACTOR, $factor->kind);
        self::assertSame('factor-1', $factor->factorId);
        self::assertSame(self::CODE, $factor->code);
        self::assertNull($factor->challengeId);
        self::assertSame([], $factor->response);

        $challenge = Submission::challenge('factor-1', 'challenge-1', self::CODE);

        self::assertSame(SubmissionKind::CHALLENGE, $challenge->kind);
        self::assertSame('factor-1', $challenge->factorId);
        self::assertSame('challenge-1', $challenge->challengeId);
        self::assertSame(self::CODE, $challenge->code);

        $recovery = Submission::recoveryCode(self::CODE);

        self::assertSame(SubmissionKind::RECOVERY_CODE, $recovery->kind);
        self::assertNull($recovery->factorId);
        self::assertSame(self::CODE, $recovery->code);

        $assertion = Submission::assertion('factor-1', ['id' => 'credential']);

        self::assertSame(SubmissionKind::ASSERTION, $assertion->kind);
        self::assertSame('factor-1', $assertion->factorId);
        self::assertSame(['id' => 'credential'], $assertion->response);
        self::assertNull($assertion->code);
    }

    /**
     * A dump shows neither a code nor a response.
     *
     * @return void
     */
    public function testADumpLeavesOutTheSecrets(): void
    {
        $code      = Submission::challenge('factor-1', 'challenge-1', self::CODE);
        $assertion = Submission::assertion('factor-1', ['signature' => 'signed-by-the-key']);

        ob_start();
        var_dump($code, $assertion); // phpcs:ignore SineMaculaLaravel.Debug.DisallowDebugStatements.Found
        $dumped = (string) ob_get_clean();

        self::assertStringNotContainsString(self::CODE, $dumped);
        self::assertStringNotContainsString('signed-by-the-key', $dumped);
        self::assertStringContainsString('challenge-1', $dumped);
        self::assertStringNotContainsString(self::CODE, print_r($code, true));
        self::assertSame(['kind' => 'challenge', 'factor_id' => 'factor-1', 'challenge_id' => 'challenge-1'], $code->__debugInfo());
    }

    /**
     * JSON shows neither a code nor a response.
     *
     * @return void
     */
    public function testJsonLeavesOutTheSecrets(): void
    {
        $encoded = (string) json_encode(Submission::assertion('factor-1', ['signature' => 'signed-by-the-key']));

        self::assertSame('{"kind":"assertion","factor_id":"factor-1","challenge_id":null}', $encoded);
    }

    /**
     * A submission is never serialised.
     *
     * @return void
     */
    public function testSerializingIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A submission holds a secret, so it is never serialised.');

        serialize(Submission::recoveryCode(self::CODE));
    }

    /**
     * A submission is never read back.
     *
     * @return void
     */
    public function testUnserializingIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A submission holds a secret, so it is never serialised.');

        Submission::recoveryCode(self::CODE)->__unserialize([]);
    }
}
