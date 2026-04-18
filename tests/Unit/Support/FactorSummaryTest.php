<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Carbon\Carbon;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Support\FactorSummary;
use Tests\Unit\Concerns\BuildsFactorSummaries;

/**
 * Unit tests for the `FactorSummary` projection.
 *
 * Covers construction via `fromFactor()`, recipient masking for email / phone /
 * short strings / empty values, and `jsonSerialize()` shape. Stub-builder
 * helpers live on the `BuildsFactorSummaries` trait so the consuming class
 * stays focused on its assertions and below the project's max-methods-per-class
 * threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class FactorSummaryTest extends TestCase
{
    use BuildsFactorSummaries;

    /** @var string */
    private const string VERIFIED_AT_ISO = '2026-04-15T12:34:56+00:00';

    /** @var string */
    private const string SAMPLE_MASKED_EMAIL = 'al***@example.com';

    /**
     * Test is final readonly class.
     *
     * @return void
     */
    public function testIsFinalReadonlyClass(): void
    {
        $reflection = new \ReflectionClass(FactorSummary::class);

        self::assertTrue($reflection->isFinal());
        self::assertTrue($reflection->isReadOnly());
    }

    /**
     * Test implements json serializable.
     *
     * @return void
     */
    public function testImplementsJsonSerializable(): void
    {
        self::assertInstanceOf(\JsonSerializable::class, $this->buildMinimalSummary());
    }

    /**
     * Test from factor captures all fields.
     *
     * @return void
     */
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

    /**
     * Test from factor stringifies integer identifier.
     *
     * @return void
     */
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

    /**
     * Test from factor collapses non scalar identifier to empty string.
     *
     * @return void
     */
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

    /**
     * Test masking keeps null recipient as null.
     *
     * @return void
     */
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

    /**
     * Test masking keeps empty string recipient as empty string.
     *
     * @return void
     */
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

    /**
     * Test masking email with short single char local part.
     *
     * @return void
     */
    public function testMaskingEmailWithShortSingleCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithRecipient('a@example.com');

        // Local-part length 1 → keep min(2, max(1, floor(1/2))) = 1 char → `a`
        // + at least one `*` → `a*@example.com`.
        self::assertSame('a*@example.com', $summary->maskedRecipient);
    }

    /**
     * Test masking email with two char local part.
     *
     * @return void
     */
    public function testMaskingEmailWithTwoCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithRecipient('ab@example.com');

        // Local-part length 2 → keep min(2, max(1, floor(2/2))) = 1 char → `a`
        // + `*` → `a*@example.com`.
        self::assertSame('a*@example.com', $summary->maskedRecipient);
    }

    /**
     * Test masking email with four char local part.
     *
     * @return void
     */
    public function testMaskingEmailWithFourCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithRecipient('abcd@example.com');

        // Local-part length 4 → keep min(2, max(1, floor(4/2))) = 2 chars →
        // `ab` + `**` → `ab**@example.com`.
        self::assertSame('ab**@example.com', $summary->maskedRecipient);
    }

    /**
     * A five-character local-part exercises the `min(2, floor(n/2))` boundary:
     * `floor(5/2) = 2` — but `ceil(5/2) = 3` and `round(5/2) = 3`, so a
     * regression that swaps `floor` for either would hand back three plaintext
     * characters. Keep the assertion exact so the mutation can't slip past.
     *
     * @return void
     */
    public function testMaskingEmailWithFiveCharLocalPartKeepsTwoCharsViaFloor(): void
    {
        $summary = $this->buildSummaryWithRecipient('alice@example.com');

        // Local-part length 5 → keep min(2, max(1, floor(5/2))) = 2 chars
        // → `al` + `***` → `al***@example.com`.
        self::assertSame('al***@example.com', $summary->maskedRecipient);
    }

    /**
     * A six-character local-part exercises the outer `min(2, …)` cap:
     * `floor(6/2) = 3`, but `min(2, 3) = 2`. A regression to `min(3, …)` would
     * expose three plaintext characters.
     *
     * @return void
     */
    public function testMaskingEmailWithSixCharLocalPartKeepsTwoCharsViaMinCap(): void
    {
        $summary = $this->buildSummaryWithRecipient('foobar@example.com');

        // Local-part length 6 → min(2, floor(6/2)) = min(2, 3) = 2 → `fo` +
        // `****` → `fo****@example.com`.
        self::assertSame('fo****@example.com', $summary->maskedRecipient);
    }

    /**
     * A recipient containing more than one `@` exercises the `explode(..., 2)`
     * limit: only the FIRST `@` may split the local-part from the domain, so a
     * second `@` belongs in the domain side untouched.
     *
     * @return void
     */
    public function testMaskingEmailHonoursExplodeLimitOnSecondAtSign(): void
    {
        $summary = $this->buildSummaryWithRecipient('alice@inner@example.com');

        // explode('@', $r, 2) → ['alice', 'inner@example.com'].
        // Local-part length 5 → keep 2, mask 3 → 'al***'.
        self::assertSame('al***@inner@example.com', $summary->maskedRecipient);
    }

    /**
     * Test masking email preserves domain.
     *
     * @return void
     */
    public function testMaskingEmailPreservesDomain(): void
    {
        $summary = $this->buildSummaryWithRecipient('alice@sub.example.com');

        self::assertStringEndsWith('@sub.example.com', (string) $summary->maskedRecipient);
    }

    /**
     * Test masking phone preserves last four digits.
     *
     * @return void
     */
    public function testMaskingPhonePreservesLastFourDigits(): void
    {
        $summary = $this->buildSummaryWithRecipient('+15551234567');

        self::assertSame('********4567', $summary->maskedRecipient);
    }

    /**
     * Test masking short strings are fully masked.
     *
     * @return void
     */
    public function testMaskingShortStringsAreFullyMasked(): void
    {
        $summary = $this->buildSummaryWithRecipient('1234');

        self::assertSame('****', $summary->maskedRecipient);
    }

    /**
     * Test masking single character recipient is fully masked.
     *
     * @return void
     */
    public function testMaskingSingleCharacterRecipientIsFullyMasked(): void
    {
        $summary = $this->buildSummaryWithRecipient('9');

        self::assertSame('*', $summary->maskedRecipient);
    }

    /**
     * Test json serialize shape with verified at.
     *
     * @return void
     */
    public function testJsonSerializeShapeWithVerifiedAt(): void
    {
        $verifiedAt = Carbon::parse(self::VERIFIED_AT_ISO);

        $summary = new FactorSummary(
            id             : '01H',
            driver         : 'email',
            label          : 'Primary',
            maskedRecipient: self::SAMPLE_MASKED_EMAIL,
            verifiedAt     : $verifiedAt,
        );

        self::assertSame([
            'id'               => '01H',
            'driver'           => 'email',
            'label'            => 'Primary',
            'masked_recipient' => self::SAMPLE_MASKED_EMAIL,
            'verified_at'      => self::VERIFIED_AT_ISO,
        ], $summary->jsonSerialize());
    }

    /**
     * Test json serialize shape with null fields.
     *
     * @return void
     */
    public function testJsonSerializeShapeWithNullFields(): void
    {
        $summary = new FactorSummary(
            id             : '01H',
            driver         : 'totp',
            label          : null,
            maskedRecipient: null,
            verifiedAt     : null,
        );

        self::assertSame([
            'id'               => '01H',
            'driver'           => 'totp',
            'label'            => null,
            'masked_recipient' => null,
            'verified_at'      => null,
        ], $summary->jsonSerialize());
    }

    /**
     * Test json encodes via json serializable.
     *
     * @return void
     */
    public function testJsonEncodesViaJsonSerializable(): void
    {
        $summary = new FactorSummary(
            id             : '01H',
            driver         : 'totp',
            label          : null,
            maskedRecipient: null,
            verifiedAt     : null,
        );

        self::assertJsonStringEqualsJsonString(
            '{"id":"01H","driver":"totp","label":null,"masked_recipient":null,"verified_at":null}',
            (string) json_encode($summary),
        );
    }
}
