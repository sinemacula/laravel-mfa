<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Carbon\Carbon;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Support\FactorSummary;

/**
 * Unit tests for the `FactorSummary` projection.
 *
 * Covers construction via `fromFactor()`, recipient masking for email / phone
 * / short strings / empty values, and `jsonSerialize()` shape.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class FactorSummaryTest extends TestCase
{
    /** @var string */
    private const string VERIFIED_AT_ISO = '2026-04-15T12:34:56+00:00';

    /** @var string */
    private const string SAMPLE_MASKED_EMAIL = self::SAMPLE_MASKED_EMAIL;

    public function testIsFinalReadonlyClass(): void
    {
        $reflection = new \ReflectionClass(FactorSummary::class);

        self::assertTrue($reflection->isFinal());
        self::assertTrue($reflection->isReadOnly());
    }

    public function testImplementsJsonSerializable(): void
    {
        self::assertInstanceOf(\JsonSerializable::class, $this->buildMinimalSummary());
    }

    public function testFromFactorCapturesAllFields(): void
    {
        $verifiedAt = Carbon::parse(self::VERIFIED_AT_ISO);

        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('01HXYZABCDEF');
        $factor->method('getDriver')->willReturn('email');
        $factor->method('getLabel')->willReturn('Work email');
        $factor->method('getRecipient')->willReturn('alice@example.com');
        $factor->method('getVerifiedAt')->willReturn($verifiedAt);

        $summary = FactorSummary::fromFactor($factor);

        self::assertSame('01HXYZABCDEF', $summary->id);
        self::assertSame('email', $summary->driver);
        self::assertSame('Work email', $summary->label);
        self::assertSame(self::SAMPLE_MASKED_EMAIL, $summary->maskedRecipient);
        self::assertSame($verifiedAt, $summary->verifiedAt);
    }

    public function testFromFactorStringifiesIntegerIdentifier(): void
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn(42);
        $factor->method('getDriver')->willReturn('totp');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getRecipient')->willReturn(null);
        $factor->method('getVerifiedAt')->willReturn(null);

        $summary = FactorSummary::fromFactor($factor);

        self::assertSame('42', $summary->id);
    }

    public function testFromFactorCollapsesNonScalarIdentifierToEmptyString(): void
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn(new \stdClass);
        $factor->method('getDriver')->willReturn('totp');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getRecipient')->willReturn(null);
        $factor->method('getVerifiedAt')->willReturn(null);

        $summary = FactorSummary::fromFactor($factor);

        self::assertSame('', $summary->id);
    }

    public function testMaskingKeepsNullRecipientAsNull(): void
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('id');
        $factor->method('getDriver')->willReturn('totp');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getRecipient')->willReturn(null);
        $factor->method('getVerifiedAt')->willReturn(null);

        $summary = FactorSummary::fromFactor($factor);

        self::assertNull($summary->maskedRecipient);
    }

    public function testMaskingKeepsEmptyStringRecipientAsEmptyString(): void
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('id');
        $factor->method('getDriver')->willReturn('totp');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getRecipient')->willReturn('');
        $factor->method('getVerifiedAt')->willReturn(null);

        $summary = FactorSummary::fromFactor($factor);

        self::assertSame('', $summary->maskedRecipient);
    }

    public function testMaskingEmailWithShortSingleCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithRecipient('a@example.com');

        // Local-part length 1 → keep min(2, max(1, floor(1/2))) = 1 char →
        // `a` + at least one `*` → `a*@example.com`.
        self::assertSame('a*@example.com', $summary->maskedRecipient);
    }

    public function testMaskingEmailWithTwoCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithRecipient('ab@example.com');

        // Local-part length 2 → keep min(2, max(1, floor(2/2))) = 1 char →
        // `a` + `*` → `a*@example.com`.
        self::assertSame('a*@example.com', $summary->maskedRecipient);
    }

    public function testMaskingEmailWithFourCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithRecipient('abcd@example.com');

        // Local-part length 4 → keep min(2, max(1, floor(4/2))) = 2 chars →
        // `ab` + `**` → `ab**@example.com`.
        self::assertSame('ab**@example.com', $summary->maskedRecipient);
    }

    public function testMaskingEmailPreservesDomain(): void
    {
        $summary = $this->buildSummaryWithRecipient('alice@sub.example.com');

        self::assertStringEndsWith('@sub.example.com', (string) $summary->maskedRecipient);
    }

    public function testMaskingPhonePreservesLastFourDigits(): void
    {
        $summary = $this->buildSummaryWithRecipient('+15551234567');

        self::assertSame('********4567', $summary->maskedRecipient);
    }

    public function testMaskingShortStringsAreFullyMasked(): void
    {
        $summary = $this->buildSummaryWithRecipient('1234');

        self::assertSame('****', $summary->maskedRecipient);
    }

    public function testMaskingSingleCharacterRecipientIsFullyMasked(): void
    {
        $summary = $this->buildSummaryWithRecipient('9');

        self::assertSame('*', $summary->maskedRecipient);
    }

    public function testJsonSerializeShapeWithVerifiedAt(): void
    {
        $verifiedAt = Carbon::parse(self::VERIFIED_AT_ISO);

        $summary = new FactorSummary(
            id: '01H',
            driver: 'email',
            label: 'Primary',
            maskedRecipient: self::SAMPLE_MASKED_EMAIL,
            verifiedAt: $verifiedAt,
        );

        self::assertSame([
            'id'               => '01H',
            'driver'           => 'email',
            'label'            => 'Primary',
            'masked_recipient' => self::SAMPLE_MASKED_EMAIL,
            'verified_at'      => '2026-04-15T12:34:56+00:00',
        ], $summary->jsonSerialize());
    }

    public function testJsonSerializeShapeWithNullFields(): void
    {
        $summary = new FactorSummary(
            id: '01H',
            driver: 'totp',
            label: null,
            maskedRecipient: null,
            verifiedAt: null,
        );

        self::assertSame([
            'id'               => '01H',
            'driver'           => 'totp',
            'label'            => null,
            'masked_recipient' => null,
            'verified_at'      => null,
        ], $summary->jsonSerialize());
    }

    public function testJsonEncodesViaJsonSerializable(): void
    {
        $summary = new FactorSummary(
            id: '01H',
            driver: 'totp',
            label: null,
            maskedRecipient: null,
            verifiedAt: null,
        );

        self::assertJsonStringEqualsJsonString(
            '{"id":"01H","driver":"totp","label":null,"masked_recipient":null,"verified_at":null}',
            (string) json_encode($summary),
        );
    }

    /**
     * Build a minimal summary for contract tests.
     *
     * @return \SineMacula\Laravel\Mfa\Support\FactorSummary
     */
    private function buildMinimalSummary(): FactorSummary
    {
        return new FactorSummary(
            id: '01H',
            driver: 'totp',
            label: null,
            maskedRecipient: null,
            verifiedAt: null,
        );
    }

    /**
     * Build a FactorSummary via `fromFactor()` for the given recipient.
     *
     * @param  string  $recipient
     * @return \SineMacula\Laravel\Mfa\Support\FactorSummary
     */
    private function buildSummaryWithRecipient(string $recipient): FactorSummary
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('id');
        $factor->method('getDriver')->willReturn('email');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getRecipient')->willReturn($recipient);
        $factor->method('getVerifiedAt')->willReturn(null);

        return FactorSummary::fromFactor($factor);
    }
}
