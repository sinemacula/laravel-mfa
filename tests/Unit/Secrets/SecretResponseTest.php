<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Secrets\SecretResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Tests for `SecretResponse`: secrets are revealed into the body, and the
 * response is never stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SecretResponse::class)]
final class SecretResponseTest extends TestCase
{
    /** @var string A TOTP secret. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /** @var string A provisioning URI carrying the secret. */
    private const string URI = 'otpauth://totp/Acme:ben%40example.test?issuer=Acme&secret=' . self::SECRET;

    /**
     * Every secret in the body is revealed, at any depth, and everything else
     * is kept.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testJsonRevealsEverySecretInTheBody(): void
    {
        $response = SecretResponse::json([
            'secret'         => new RevealedSecret(self::SECRET),
            'factor'         => ['id' => '01J0', 'provisioning_uri' => new RevealedSecret(self::URI)],
            'recovery_codes' => [new RevealedSecret('ABCD-EFGH-JKLM'), new RevealedSecret('NPQR-STUV-WXYZ')],
            'expires_in'     => 900,
        ]);

        self::assertSame([
            'secret'         => self::SECRET,
            'factor'         => ['id' => '01J0', 'provisioning_uri' => self::URI],
            'recovery_codes' => ['ABCD-EFGH-JKLM', 'NPQR-STUV-WXYZ'],
            'expires_in'     => 900,
        ], json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR));
    }

    /**
     * The JSON response is sent with `no-store`, so no cache keeps it.
     *
     * @return void
     */
    public function testJsonIsNeverStored(): void
    {
        $response = SecretResponse::json(['secret' => new RevealedSecret(self::SECRET)]);

        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
    }

    /**
     * The status and headers given are kept.
     *
     * @return void
     */
    public function testJsonKeepsTheStatusAndHeaders(): void
    {
        $response = SecretResponse::json([], 201, ['X-Request-Id' => 'abc']);

        self::assertSame(201, $response->getStatusCode());
        self::assertSame('abc', $response->headers->get('X-Request-Id'));
    }

    /**
     * Any response can be sent without being stored, and the same response is
     * returned.
     *
     * @return void
     */
    public function testWithoutStoringMarksAnyResponse(): void
    {
        $response = new Response('secret page');

        self::assertSame($response, SecretResponse::withoutStoring($response));
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
    }

    /**
     * Caching the response allowed is replaced, not added to.
     *
     * @return void
     */
    public function testWithoutStoringReplacesTheCachingAllowed(): void
    {
        $response = SecretResponse::withoutStoring(new Response('', 200, ['Cache-Control' => 'public, max-age=3600']));

        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        self::assertFalse($response->headers->hasCacheControlDirective('public'));
        self::assertFalse($response->headers->hasCacheControlDirective('max-age'));
    }
}
