<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Exceptions\MissingRecipientException;
use SineMacula\Laravel\Mfa\Gateways\FakeSmsGateway;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Unit tests for `SmsDriver`.
 *
 * Exercises the SMS-gateway dispatch path, the missing-recipient
 * guard, the message-template substitution, and the end-to-end
 * challenge-issuance path against the in-memory `FakeSmsGateway`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class SmsDriverTest extends TestCase
{
    /**
     * `dispatch()` must reject a null recipient with a clear
     * `MissingRecipientException` rather than silently dropping the
     * outbound message.
     *
     * @return void
     */
    public function testDispatchThrowsWhenRecipientIsNull(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeFactor(recipient: null);

        $this->expectException(MissingRecipientException::class);
        $this->expectExceptionMessage('SMS factor has no recipient configured');

        $driver->issueChallenge($factor);
    }

    /**
     * `dispatch()` must reject an empty-string recipient identically
     * to a null one.
     *
     * @return void
     */
    public function testDispatchThrowsWhenRecipientIsEmptyString(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeFactor(recipient: '');

        $this->expectException(MissingRecipientException::class);

        $driver->issueChallenge($factor);
    }

    /**
     * The default message template must substitute the issued code
     * into the `:code` placeholder.
     *
     * @return void
     */
    public function testDispatchSubstitutesCodePlaceholderInDefaultTemplate(): void
    {
        $gateway = new FakeSmsGateway;
        $driver  = new SmsDriver(gateway: $gateway);
        $factor  = $this->makeFactor(recipient: '+441234567890');

        $driver->issueChallenge($factor);

        $sent = $gateway->sentTo('+441234567890');

        self::assertCount(1, $sent);

        $message = $sent[0]['message'];

        self::assertStringStartsWith('Your verification code is: ', $message);
        self::assertMatchesRegularExpression(
            '/^Your verification code is: \d{6}$/',
            $message,
        );
    }

    /**
     * A constructor-supplied custom message template must be honoured
     * verbatim with the `:code` placeholder substituted in place.
     *
     * @return void
     */
    public function testDispatchUsesCustomMessageTemplate(): void
    {
        $gateway  = new FakeSmsGateway;
        $template = 'OTP :code — keep it secret.';
        $driver   = new SmsDriver(
            gateway: $gateway,
            messageTemplate: $template,
        );
        $factor = $this->makeFactor(recipient: '+441111111111');

        $driver->issueChallenge($factor);

        $sent    = $gateway->sentTo('+441111111111');
        $message = $sent[0]['message'];

        self::assertMatchesRegularExpression(
            '/^OTP \d{6} — keep it secret\.$/',
            $message,
        );
    }

    /**
     * `getMessageTemplate()` must return the shipped default when no
     * override is supplied to the constructor.
     *
     * @return void
     */
    public function testGetMessageTemplateReturnsDefault(): void
    {
        $driver = $this->makeDriver();

        self::assertSame(
            'Your verification code is: :code',
            $driver->getMessageTemplate(),
        );
    }

    /**
     * `getMessageTemplate()` must return the constructor-supplied
     * custom template verbatim.
     *
     * @return void
     */
    public function testGetMessageTemplateReturnsCustomValue(): void
    {
        $driver = new SmsDriver(
            gateway: new FakeSmsGateway,
            messageTemplate: 'Code: :code',
        );

        self::assertSame('Code: :code', $driver->getMessageTemplate());
    }

    /**
     * Issuing a challenge against the bound `FakeSmsGateway` must
     * record the outbound message and persist a fresh code + expiry
     * on the underlying factor row.
     *
     * @return void
     */
    public function testIssueChallengeEndToEndWithFakeGateway(): void
    {
        $gateway = new FakeSmsGateway;

        $this->container()->instance(SmsGateway::class, $gateway);

        $driver = new SmsDriver(gateway: $gateway);
        $factor = $this->makeFactor(recipient: '+447000000000');

        $driver->issueChallenge($factor);

        self::assertCount(1, $gateway->sentTo('+447000000000'));

        $factor->refresh();

        $code = $factor->getCode();

        self::assertNotNull($code);
        self::assertMatchesRegularExpression('/^\d{6}$/', $code);
        self::assertNotNull($factor->getExpiresAt());
    }

    /**
     * A configured alphabet (e.g. hex) must be honoured by the issued
     * code so consumers can override the default zero-padded numeric.
     *
     * @return void
     */
    public function testDispatchUsesConfiguredAlphabet(): void
    {
        $gateway = new FakeSmsGateway;
        $driver  = new SmsDriver(
            gateway: $gateway,
            codeLength: 8,
            alphabet: '0123456789ABCDEF',
        );
        $factor = $this->makeFactor(recipient: '+442222222222');

        $driver->issueChallenge($factor);

        $sent    = $gateway->sentTo('+442222222222');
        $message = $sent[0]['message'];

        self::assertMatchesRegularExpression(
            '/^Your verification code is: [0-9A-F]{8}$/',
            $message,
        );
    }

    /**
     * Build an `SmsDriver` with a fresh `FakeSmsGateway`.
     *
     * @return \SineMacula\Laravel\Mfa\Drivers\SmsDriver
     */
    private function makeDriver(): SmsDriver
    {
        return new SmsDriver(gateway: new FakeSmsGateway);
    }

    /**
     * Persist and return a fresh SMS factor owned by a freshly
     * inserted test user.
     *
     * @param  ?string  $recipient
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function makeFactor(?string $recipient): FactorModel
    {
        $user = TestUser::query()->create([
            'email'       => 'owner@example.com',
            'mfa_enabled' => true,
        ]);

        $factor                       = new FactorModel;
        $factor->driver               = 'sms';
        $factor->recipient            = $recipient;
        $factor->authenticatable_type = $user->getMorphClass();
        $factor->authenticatable_id   = (string) $user->id;
        $factor->save();

        return $factor;
    }
}
