<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Support\Facades\Mail;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Exceptions\MissingRecipientException;
use SineMacula\Laravel\Mfa\Mail\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Unit tests for `EmailDriver`.
 *
 * Exercises the Laravel mailer dispatch path (via `Mail::fake()`), the
 * missing-recipient guard, the Mailable class override, and the
 * end-to-end challenge-issuance happy path persisting a real
 * `Factor` row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class EmailDriverTest extends TestCase
{
    public function testDispatchThrowsWhenRecipientIsNull(): void
    {
        Mail::fake();

        $driver = $this->makeDriver();
        $factor = $this->makeFactor(recipient: null);

        $this->expectException(MissingRecipientException::class);
        $this->expectExceptionMessage('Email factor has no recipient configured');

        $driver->issueChallenge($factor);
    }

    public function testDispatchThrowsWhenRecipientIsEmptyString(): void
    {
        Mail::fake();

        $driver = $this->makeDriver();
        $factor = $this->makeFactor(recipient: '');

        $this->expectException(MissingRecipientException::class);

        $driver->issueChallenge($factor);
    }

    public function testDispatchSendsDefaultMailableToRecipient(): void
    {
        Mail::fake();

        $driver = $this->makeDriver();
        $factor = $this->makeFactor(recipient: 'user@example.com');

        $driver->issueChallenge($factor);

        Mail::assertSent(
            MfaCodeMessage::class,
            static fn (MfaCodeMessage $mail): bool => $mail->hasTo('user@example.com')
                    && $mail->expiresInMinutes              === 10
                    && preg_match('/^\d{6}$/', $mail->code) === 1,
        );
    }

    public function testDispatchUsesCustomMailableClass(): void
    {
        Mail::fake();

        $driver = $this->makeDriver(mailable: CustomMfaCodeMessage::class);
        $factor = $this->makeFactor(recipient: 'brand@example.com');

        $driver->issueChallenge($factor);

        Mail::assertSent(
            CustomMfaCodeMessage::class,
            static fn (CustomMfaCodeMessage $mail): bool => $mail->hasTo('brand@example.com'),
        );
    }

    public function testGetMailableReturnsConstructorValue(): void
    {
        $driver = $this->makeDriver(mailable: CustomMfaCodeMessage::class);

        self::assertSame(CustomMfaCodeMessage::class, $driver->getMailable());
    }

    public function testGetMailableDefaultsToMfaCodeMessage(): void
    {
        $driver = $this->makeDriver();

        self::assertSame(MfaCodeMessage::class, $driver->getMailable());
    }

    public function testIssueChallengePersistsCodeAndExpiry(): void
    {
        Mail::fake();

        $driver = $this->makeDriver();
        $factor = $this->makeFactor(recipient: 'persist@example.com');

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
     * Build an `EmailDriver` with the container's mailer and an
     * optional Mailable override.
     *
     * @param  class-string<MfaCodeMessage>  $mailable
     */
    private function makeDriver(string $mailable = MfaCodeMessage::class): EmailDriver
    {
        /** @var Mailer $mailer */
        $mailer = $this->app->make(Mailer::class);

        return new EmailDriver(
            mailer: $mailer,
            mailable: $mailable,
        );
    }

    /**
     * Persist and return a fresh email factor owned by a freshly
     * inserted test user.
     *
     * @param  ?string  $recipient
     */
    private function makeFactor(?string $recipient): FactorModel
    {
        $user = TestUser::query()->create([
            'email'       => 'owner@example.com',
            'mfa_enabled' => true,
        ]);

        $factor                       = new FactorModel;
        $factor->driver               = 'email';
        $factor->recipient            = $recipient;
        $factor->authenticatable_type = $user->getMorphClass();
        $factor->authenticatable_id   = (string) $user->getKey();
        $factor->save();

        return $factor;
    }
}

/**
 * Custom Mailable subclass used to verify the constructor-configurable
 * `$mailable` class argument is honoured by the driver.
 *
 * @internal
 */
final class CustomMfaCodeMessage extends MfaCodeMessage {}
