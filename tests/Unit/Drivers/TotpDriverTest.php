<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PragmaRX\Google2FA\Google2FA;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use Tests\Fixtures\TotpStubFactor;
use Tests\TestCase;

/**
 * Unit tests for `TotpDriver`.
 *
 * Exercises the Google2FA-backed verification path, secret generation, and the
 * implicit-challenge (no-op) contract for the TOTP driver.
 *
 * The missing-dependency constructor branch (`Google2FA` class
 * absent) is not exercised here — `pragmarx/google2fa` is installed
 * as a `require-dev` dependency, making it impossible to simulate the
 * absent-class condition from inside the autoloaded test process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class TotpDriverTest extends TestCase
{
    /** @var string Account-name fixture used across the provisioning-URI tests. */
    private const string ACCOUNT_NAME = 'user@example.com';

    /**
     * `issueChallenge()` must be a no-op for TOTP — the code is generated
     * client-side from the shared secret.
     *
     * @return void
     */
    public function testIssueChallengeIsNoOp(): void
    {
        $driver = new TotpDriver;
        $factor = $this->makeFactor(secret: 'IGNORED');

        // No return value, no state mutation, no exception — the TOTP
        // challenge is generated client-side.
        $driver->issueChallenge($factor);

        self::assertSame('IGNORED', $factor->getSecret());
    }

    /**
     * A null stored secret must short-circuit verify to false.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenSecretIsNull(): void
    {
        $driver = new TotpDriver;
        $factor = $this->makeFactor(secret: null);

        self::assertFalse($driver->verify($factor, '123456'));
    }

    /**
     * An empty stored secret must short-circuit verify to false.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenSecretIsEmptyString(): void
    {
        $driver = new TotpDriver;
        $factor = $this->makeFactor(secret: '');

        self::assertFalse($driver->verify($factor, '123456'));
    }

    /**
     * A current TOTP code derived from the stored secret must verify
     * successfully.
     *
     * @return void
     */
    public function testVerifyReturnsTrueForCurrentTotpCode(): void
    {
        $google2fa = new Google2FA;
        $secret    = $google2fa->generateSecretKey();
        $code      = $google2fa->getCurrentOtp($secret);

        $driver = new TotpDriver;
        $factor = $this->makeFactor(secret: $secret);

        self::assertTrue($driver->verify($factor, $code));
    }

    /**
     * A code that does not match the current TOTP for the stored secret must
     * fail verification.
     *
     * @return void
     */
    public function testVerifyReturnsFalseForWrongCode(): void
    {
        $google2fa = new Google2FA;
        $secret    = $google2fa->generateSecretKey();

        $driver = new TotpDriver;
        $factor = $this->makeFactor(secret: $secret);

        // '000000' is astronomically unlikely to be the current TOTP
        // for a freshly generated secret — the Google2FA algorithm
        // draws from 10^6 candidates across the active window.
        self::assertFalse($driver->verify($factor, '000000'));
    }

    /**
     * `generateSecret()` must return a non-empty Base32 string ready for
     * handing to an authenticator app.
     *
     * @return void
     */
    public function testGenerateSecretReturnsNonEmptyBase32String(): void
    {
        $driver = new TotpDriver;
        $secret = $driver->generateSecret();

        self::assertIsString($secret);
        self::assertNotSame('', $secret);
        self::assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret);
    }

    /**
     * The provisioning URI must use the `otpauth://totp/` scheme so
     * authenticator apps can render it as a QR code.
     *
     * @return void
     */
    public function testProvisioningUriReturnsOtpauthScheme(): void
    {
        $driver = new TotpDriver;
        $secret = $driver->generateSecret();

        $uri = $driver->provisioningUri(
            issuer: 'Acme',
            accountName: self::ACCOUNT_NAME,
            secret: $secret,
        );

        self::assertStringStartsWith('otpauth://totp/', $uri);
    }

    /**
     * The provisioning URI must carry the issuer, account name, and secret in
     * both the label and the query parameters.
     *
     * @return void
     */
    public function testProvisioningUriIncludesIssuerAndAccountAndSecret(): void
    {
        $driver = new TotpDriver;
        $secret = $driver->generateSecret();

        $uri = $driver->provisioningUri(
            issuer: 'Acme',
            accountName: self::ACCOUNT_NAME,
            secret: $secret,
        );

        // The label segment is `Issuer:AccountName`, URL-encoded by the
        // Google2FA library — assert the joined form so the test is not
        // satisfied by the `issuer=Acme` query parameter alone.
        self::assertStringContainsString('Acme:user%40example.com', $uri);

        // Both the `secret` and `issuer` query parameters must be present
        // (the latter is the standard auth-app behaviour for grouping).
        $query = parse_url($uri, PHP_URL_QUERY);
        self::assertIsString($query);

        parse_str($query, $params);

        self::assertArrayHasKey('secret', $params);
        self::assertSame($secret, $params['secret']);
        self::assertArrayHasKey('issuer', $params);
        self::assertSame('Acme', $params['issuer']);
    }

    /**
     * The provisioning URI must encode an issuer containing whitespace exactly
     * once — never doubly encoded.
     *
     * @return void
     */
    public function testProvisioningUriDoesNotDoubleEncodeIssuer(): void
    {
        $driver = new TotpDriver;
        $secret = $driver->generateSecret();

        $uri = $driver->provisioningUri(
            issuer: 'Acme Co',
            accountName: self::ACCOUNT_NAME,
            secret: $secret,
        );

        // `Acme Co` should be encoded exactly once. A double-encoded value
        // would surface as `Acme%2520Co`; the wrapper must trust the
        // library's single pass.
        self::assertStringNotContainsString('Acme%2520Co', $uri);
        self::assertStringContainsString('Acme%20Co', $uri);
    }

    /**
     * The `$secret` parameter on `provisioningUri()` must carry the
     * `#[\SensitiveParameter]` attribute so it never leaks into a stack trace.
     *
     * @return void
     */
    public function testProvisioningUriSecretParameterCarriesSensitiveAttribute(): void
    {
        $reflection  = new \ReflectionMethod(TotpDriver::class, 'provisioningUri');
        $secretParam = $reflection->getParameters()[2] ?? null;

        self::assertNotNull($secretParam);
        self::assertSame('secret', $secretParam->getName());
        self::assertNotEmpty(
            $secretParam->getAttributes(\SensitiveParameter::class),
            'The $secret parameter must carry the #[\SensitiveParameter] '
            . 'attribute so it does not leak into stack traces.',
        );
    }

    /**
     * Build an in-memory `Factor` stub exposing the given stored secret so the
     * verify branches can be exercised without hitting the database.
     *
     * @param  ?string  $secret
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    private function makeFactor(#[\SensitiveParameter] ?string $secret): Factor
    {
        return new TotpStubFactor($secret);
    }
}
