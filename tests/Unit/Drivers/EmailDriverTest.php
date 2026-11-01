<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Support\Facades\Mail;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Exceptions\MissingDestinationException;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use Tests\Fixtures\Codes\CustomMfaCodeMessage;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Unit tests for `EmailDriver`.
 *
 * Exercises the Laravel mailer dispatch path (via `Mail::fake()`), the
 * missing-destination guard, the Mailable class override, and the end-to-end
 * challenge-issuance happy path persisting a real `Factor` row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EmailDriver::class)]
final class EmailDriverTest extends TestCase
{
    /**
     * `dispatch()` must reject a null destination with a clear
     * `MissingDestinationException` rather than silently dropping the outbound
     * mail.
     *
     * @return void
     */
    public function testDispatchThrowsWhenDestinationIsNull(): void
    {
        Mail::fake();

        $driver = $this->makeDriver();
        $factor = $this->makeFactor(destination: null);

        $this->expectException(MissingDestinationException::class);
        $this->expectExceptionMessage('Email factor has no destination configured');

        $driver->issueChallenge($factor);
    }

    /**
     * `dispatch()` must reject an empty-string destination identically to a
     * null one.
     *
     * @return void
     */
    public function testDispatchThrowsWhenDestinationIsEmptyString(): void
    {
        Mail::fake();

        $driver = $this->makeDriver();
        $factor = $this->makeFactor(destination: '');

        $this->expectException(MissingDestinationException::class);

        $driver->issueChallenge($factor);
    }

    /**
     * Issuing a challenge with a configured destination should send the default
     * `MfaCodeMessage` Mailable to that address with a fresh 6-digit numeric
     * code and the configured 10-minute expiry.
     *
     * @return void
     */
    public function testDispatchSendsDefaultMailableToDestination(): void
    {
        Mail::fake();

        $driver = $this->makeDriver();
        $factor = $this->makeFactor(destination: 'user@example.com');

        $driver->issueChallenge($factor);

        Mail::assertSent(
            MfaCodeMessage::class,
            static fn (MfaCodeMessage $mail): bool => $mail->hasTo('user@example.com')
                    && $mail->expiresInMinutes              === 10
                    && preg_match('/^\d{6}$/', $mail->code) === 1,
        );
    }

    /**
     * The driver must honour a constructor-supplied custom Mailable class so
     * consumers can ship branded message templates.
     *
     * @return void
     */
    public function testDispatchUsesCustomMailableClass(): void
    {
        Mail::fake();

        $driver = $this->makeDriver(mailable: CustomMfaCodeMessage::class);
        $factor = $this->makeFactor(destination: 'brand@example.com');

        $driver->issueChallenge($factor);

        Mail::assertSent(
            CustomMfaCodeMessage::class,
            static fn (CustomMfaCodeMessage $mail): bool => $mail->hasTo('brand@example.com'),
        );
    }

    /**
     * `getMailable()` must return the constructor-supplied class verbatim.
     *
     * @return void
     */
    public function testGetMailableReturnsConstructorValue(): void
    {
        $driver = $this->makeDriver(mailable: CustomMfaCodeMessage::class);

        self::assertSame(CustomMfaCodeMessage::class, $driver->getMailable());
    }

    /**
     * Without an explicit constructor argument `getMailable()` must fall back
     * to the shipped `MfaCodeMessage` default.
     *
     * @return void
     */
    public function testGetMailableDefaultsToMfaCodeMessage(): void
    {
        $driver = $this->makeDriver();

        self::assertSame(MfaCodeMessage::class, $driver->getMailable());
    }

    /**
     * After issuing a challenge the underlying factor row must carry a freshly
     * issued numeric code with a future expiry.
     *
     * @return void
     */
    public function testIssueChallengePersistsCodeAndExpiry(): void
    {
        Mail::fake();

        $driver = $this->makeDriver();
        $factor = $this->makeFactor(destination: 'persist@example.com');

        $driver->issueChallenge($factor);
        $factor->refresh();

        $code    = $factor->getCode();
        $expires = $factor->getExpiresAt();

        self::assertNotNull($code);
        self::assertMatchesRegularExpression('/^\d{6}$/', $code);
        self::assertNotNull($expires);
        self::assertTrue($expires->isFuture());
    }

    /**
     * A configured code length must be honoured by the issued code, which stays
     * numeric.
     *
     * @return void
     */
    public function testDispatchUsesConfiguredCodeLength(): void
    {
        Mail::fake();

        $mailer = app(Mailer::class);

        $driver = new EmailDriver(
            mailer: $mailer,
            codeLength: 8,
        );
        $factor = $this->makeFactor(destination: 'length@example.com');

        $driver->issueChallenge($factor);

        Mail::assertSent(
            MfaCodeMessage::class,
            static fn (MfaCodeMessage $mail): bool => $mail->hasTo('length@example.com')
                    && preg_match('/^\d{8}$/', $mail->code) === 1,
        );
    }

    /**
     * Build an `EmailDriver` with the container's mailer and an optional
     * Mailable override.
     *
     * @param  class-string<\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage>  $mailable
     * @return \SineMacula\Laravel\Mfa\Drivers\EmailDriver
     */
    private function makeDriver(string $mailable = MfaCodeMessage::class): EmailDriver
    {
        $mailer = app(Mailer::class);

        return new EmailDriver(
            mailer: $mailer,
            mailable: $mailable,
        );
    }

    /**
     * Persist and return a fresh email factor owned by a freshly inserted test
     * user.
     *
     * @param  ?string  $destination
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function makeFactor(?string $destination): FactorModel
    {
        $user = TestUser::query()->create([
            'email'       => 'owner@example.com',
            'mfa_enabled' => true,
        ]);

        $factor                       = new FactorModel;
        $factor->type                 = 'email';
        $factor->destination          = $destination;
        $factor->authenticatable_type = $user->getMorphClass();
        $factor->authenticatable_id   = (string) $user->id;
        $factor->save();

        return $factor;
    }
}
