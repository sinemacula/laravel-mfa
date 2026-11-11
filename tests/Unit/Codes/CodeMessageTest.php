<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Verification\Dumps;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeMessage::class)]
final class CodeMessageTest extends TestCase
{
    /** @var string The code the message carries. */
    private const string CODE = '482915';

    /** @var string The destination the message names. */
    private const string DESTINATION = 'ada.lovelace@example.test';

    /** @var string The recipient's identifier. */
    private const string RECIPIENT = 'recipient-key-7731';

    /**
     * @return void
     */
    public function testTheMessageCarriesWhatItWasBuiltWith(): void
    {
        $recipient = new NonEloquentIdentity(self::RECIPIENT);
        $factor    = FactorSummary::fromFactor(new InMemoryFactor(type: 'email', destination: self::DESTINATION));
        $expiresAt = CarbonImmutable::parse('2026-11-04 12:10:00');
        $message   = self::message($recipient, $factor, $expiresAt);

        self::assertSame('web', $message->application);
        self::assertSame(Purpose::ENROLLMENT, $message->purpose);
        self::assertSame('email', $message->type);
        self::assertSame(self::DESTINATION, $message->destination());
        self::assertSame(self::CODE, $message->code->reveal());
        self::assertSame($expiresAt, $message->expiresAt);
        self::assertSame($recipient, $message->recipient());
        self::assertSame($factor, $message->factor);
    }

    /**
     * @return void
     */
    public function testNoDumpShowsTheCodeTheDestinationOrTheRecipient(): void
    {
        $message = self::message(
            new NonEloquentIdentity(self::RECIPIENT),
            FactorSummary::fromFactor(new InMemoryFactor(type: 'email', destination: self::DESTINATION)),
            CarbonImmutable::now(),
        );

        foreach (Dumps::of($message) as $way => $dump) {
            self::assertStringNotContainsString(self::CODE, $dump, $way);
            self::assertStringNotContainsString(self::DESTINATION, $dump, $way);
            self::assertStringNotContainsString(self::RECIPIENT, $dump, $way);
        }
    }

    /**
     * @param  \Tests\Fixtures\Identities\NonEloquentIdentity  $recipient
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return \SineMacula\Laravel\Mfa\Codes\CodeMessage
     */
    private static function message(NonEloquentIdentity $recipient, FactorSummary $factor, CarbonImmutable $expiresAt): CodeMessage
    {
        return new CodeMessage(
            application: 'web',
            purpose    : Purpose::ENROLLMENT,
            type       : 'email',
            destination: self::DESTINATION,
            code       : new RevealedSecret(self::CODE),
            expiresAt  : $expiresAt,
            recipient  : $recipient,
            factor     : $factor,
        );
    }
}
