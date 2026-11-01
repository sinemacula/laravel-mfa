<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Http\JsonResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Tests for `RevealedSecret`: the plaintext leaves only through `reveal()`, and
 * every other way out refuses or shows a marker.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevealedSecret::class)]
final class RevealedSecretTest extends TestCase
{
    /** @var string A TOTP secret to hold. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /**
     * Revealing gives the plaintext.
     *
     * @return void
     */
    public function testRevealGivesThePlaintext(): void
    {
        self::assertSame(self::SECRET, (new RevealedSecret(self::SECRET))->reveal());
    }

    /**
     * Casting to a string refuses.
     *
     * @return void
     */
    public function testRefusesToCastToAString(): void
    {
        $secret = new RevealedSecret(self::SECRET);

        $this->expectException(SecretNotRevealedException::class);
        $this->expectExceptionMessage('A secret cannot be cast to a string: call reveal() where it is shown.');

        self::fail('Cast to ' . $secret);
    }

    /**
     * Encoding as JSON refuses.
     *
     * @return void
     */
    public function testRefusesToEncodeAsJson(): void
    {
        $secret = new RevealedSecret(self::SECRET);

        $this->expectException(SecretNotRevealedException::class);
        $this->expectExceptionMessage('A secret cannot be encoded as JSON: send it with SecretResponse::json().');

        self::fail((string) json_encode(['secret' => $secret]));
    }

    /**
     * A JSON response built around the secret refuses, so it never reaches a
     * body sent without `no-store`.
     *
     * @return void
     */
    public function testRefusesToEncodeIntoAJsonResponse(): void
    {
        $secret = new RevealedSecret(self::SECRET);

        $this->expectException(SecretNotRevealedException::class);

        $response = new JsonResponse(['secret' => $secret]);

        self::fail((string) $response->getContent());
    }

    /**
     * Serialising refuses, alone or inside another value.
     *
     * @return void
     */
    public function testRefusesToSerialize(): void
    {
        $secret = new RevealedSecret(self::SECRET);

        $this->expectException(SecretNotRevealedException::class);
        $this->expectExceptionMessage('A secret cannot be serialised.');

        self::fail(serialize(['secret' => $secret]));
    }

    /**
     * Unserialising a stored payload refuses.
     *
     * @return void
     */
    public function testRefusesToUnserialize(): void
    {
        $payload = sprintf('O:%d:"%s":0:{}', strlen(RevealedSecret::class), RevealedSecret::class);

        $this->expectException(SecretNotRevealedException::class);
        $this->expectExceptionMessage('A secret cannot be unserialised.');

        self::fail(gettype(unserialize($payload)));
    }

    /**
     * `print_r` shows no plaintext.
     *
     * @return void
     */
    public function testPrintRShowsNoPlaintext(): void
    {
        $output = print_r(new RevealedSecret(self::SECRET), true);

        self::assertStringNotContainsString(self::SECRET, $output);
        self::assertStringContainsString(RevealedSecret::REDACTED, $output);
    }

    /**
     * `var_dump` shows no plaintext.
     *
     * @return void
     */
    public function testVarDumpShowsNoPlaintext(): void
    {
        ob_start();

        var_dump(new RevealedSecret(self::SECRET));

        $output = (string) ob_get_clean();

        self::assertStringNotContainsString(self::SECRET, $output);
        self::assertStringContainsString(RevealedSecret::REDACTED, $output);
    }

    /**
     * `var_export` shows no plaintext.
     *
     * @return void
     */
    public function testVarExportShowsNoPlaintext(): void
    {
        $output = var_export(new RevealedSecret(self::SECRET), true);

        self::assertStringNotContainsString(self::SECRET, $output);
    }

    /**
     * Symfony's VarDumper, behind Laravel's dump helpers, shows no plaintext.
     *
     * @return void
     */
    public function testVarDumperShowsNoPlaintext(): void
    {
        $output = (string) (new CliDumper)->dump((new VarCloner)->cloneVar(new RevealedSecret(self::SECRET)), true);

        self::assertStringNotContainsString(self::SECRET, $output);
        self::assertStringContainsString(RevealedSecret::REDACTED, $output);
    }

    /**
     * The debug information is the marker alone.
     *
     * @return void
     */
    public function testDebugInfoIsTheMarker(): void
    {
        self::assertSame(['secret' => '[redacted]'], (new RevealedSecret(self::SECRET))->__debugInfo());
    }
}
