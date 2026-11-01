<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use Carbon\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use Tests\Unit\Concerns\BuildsFactorSummaries;

/**
 * Unit tests for the `FactorSummary` projection.
 *
 * Covers construction via `fromFactor()`, destination masking for email / phone
 * / short strings / empty values, and `jsonSerialize()` shape. Stub-builder
 * helpers live on the `BuildsFactorSummaries` trait so the consuming class
 * stays focused on its assertions and below the project's max-methods-per-class
 * threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorSummary::class)]
final class FactorSummaryTest extends TestCase
{
    use BuildsFactorSummaries;

    /** @var string */
    private const string LAST_USED_AT_ISO = '2026-04-15T12:34:56+00:00';

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
        $lastUsedAt = Carbon::parse(self::LAST_USED_AT_ISO);

        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('01HXYZABCDEF');
        $factor->method('getType')->willReturn('email');
        $factor->method('getLabel')->willReturn('Work email');
        $factor->method('getDestination')->willReturn('alice@example.com');
        $factor->method('getStatus')->willReturn(FactorStatus::PENDING);
        $factor->method('isPreferred')->willReturn(true);
        $factor->method('getLastUsedAt')->willReturn($lastUsedAt);

        $summary = FactorSummary::fromFactor($factor);

        self::assertSame('01HXYZABCDEF', $summary->id);
        self::assertSame('email', $summary->type);
        self::assertSame('Work email', $summary->label);
        self::assertSame(self::SAMPLE_MASKED_EMAIL, $summary->maskedDestination);
        self::assertSame(FactorStatus::PENDING, $summary->status);
        self::assertTrue($summary->preferred);
        self::assertSame($lastUsedAt, $summary->lastUsedAt);
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
        $factor->method('getType')->willReturn('totp');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getDestination')->willReturn(null);
        $factor->method('getStatus')->willReturn(FactorStatus::CONFIRMED);
        $factor->method('getLastUsedAt')->willReturn(null);

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
        $factor->method('getType')->willReturn('totp');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getDestination')->willReturn(null);
        $factor->method('getStatus')->willReturn(FactorStatus::CONFIRMED);
        $factor->method('getLastUsedAt')->willReturn(null);

        $summary = FactorSummary::fromFactor($factor);

        self::assertSame('', $summary->id);
    }

    /**
     * Test masking keeps null destination as null.
     *
     * @return void
     */
    public function testMaskingKeepsNullDestinationAsNull(): void
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('id');
        $factor->method('getType')->willReturn('totp');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getDestination')->willReturn(null);
        $factor->method('getStatus')->willReturn(FactorStatus::CONFIRMED);
        $factor->method('getLastUsedAt')->willReturn(null);

        $summary = FactorSummary::fromFactor($factor);

        self::assertNull($summary->maskedDestination);
    }

    /**
     * Test masking keeps empty string destination as empty string.
     *
     * @return void
     */
    public function testMaskingKeepsEmptyStringDestinationAsEmptyString(): void
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('id');
        $factor->method('getType')->willReturn('totp');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getDestination')->willReturn('');
        $factor->method('getStatus')->willReturn(FactorStatus::CONFIRMED);
        $factor->method('getLastUsedAt')->willReturn(null);

        $summary = FactorSummary::fromFactor($factor);

        self::assertSame('', $summary->maskedDestination);
    }

    /**
     * Test masking email with short single char local part.
     *
     * @return void
     */
    public function testMaskingEmailWithShortSingleCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithDestination('a@example.com');

        // Local-part length 1 → keep min(2, max(1, floor(1/2))) = 1 char → `a`
        // + at least one `*` → `a*@example.com`.
        self::assertSame('a*@example.com', $summary->maskedDestination);
    }

    /**
     * Test masking email with two char local part.
     *
     * @return void
     */
    public function testMaskingEmailWithTwoCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithDestination('ab@example.com');

        // Local-part length 2 → keep min(2, max(1, floor(2/2))) = 1 char → `a`
        // + `*` → `a*@example.com`.
        self::assertSame('a*@example.com', $summary->maskedDestination);
    }

    /**
     * Test masking email with four char local part.
     *
     * @return void
     */
    public function testMaskingEmailWithFourCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithDestination('abcd@example.com');

        // Local-part length 4 → keep min(2, max(1, floor(4/2))) = 2 chars →
        // `ab` + `**` → `ab**@example.com`.
        self::assertSame('ab**@example.com', $summary->maskedDestination);
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
        $summary = $this->buildSummaryWithDestination('alice@example.com');

        // Local-part length 5 → keep min(2, max(1, floor(5/2))) = 2 chars →
        // `al` + `***` → `al***@example.com`.
        self::assertSame('al***@example.com', $summary->maskedDestination);
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
        $summary = $this->buildSummaryWithDestination('foobar@example.com');

        // Local-part length 6 → min(2, floor(6/2)) = min(2, 3) = 2 → `fo` +
        // `****` → `fo****@example.com`.
        self::assertSame('fo****@example.com', $summary->maskedDestination);
    }

    /**
     * A destination containing more than one `@` exercises the `explode(...,
     * 2)` limit: only the FIRST `@` may split the local-part from the domain,
     * so a second `@` belongs in the domain side untouched.
     *
     * @return void
     */
    public function testMaskingEmailHonorsExplodeLimitOnSecondAtSign(): void
    {
        $summary = $this->buildSummaryWithDestination('alice@inner@example.com');

        // explode('@', $r, 2) → ['alice', 'inner@example.com']. Local-part
        // length 5 → keep 2, mask 3 → 'al***'.
        self::assertSame('al***@inner@example.com', $summary->maskedDestination);
    }

    /**
     * Test masking email preserves domain.
     *
     * @return void
     */
    public function testMaskingEmailPreservesDomain(): void
    {
        $summary = $this->buildSummaryWithDestination('alice@sub.example.com');

        self::assertStringEndsWith('@sub.example.com', (string) $summary->maskedDestination);
    }

    /**
     * Test masking phone preserves last four digits.
     *
     * @return void
     */
    public function testMaskingPhonePreservesLastFourDigits(): void
    {
        $summary = $this->buildSummaryWithDestination('+15551234567');

        self::assertSame('********4567', $summary->maskedDestination);
    }

    /**
     * Test masking short strings are fully masked.
     *
     * @return void
     */
    public function testMaskingShortStringsAreFullyMasked(): void
    {
        $summary = $this->buildSummaryWithDestination('1234');

        self::assertSame('****', $summary->maskedDestination);
    }

    /**
     * Test masking single character destination is fully masked.
     *
     * @return void
     */
    public function testMaskingSingleCharacterDestinationIsFullyMasked(): void
    {
        $summary = $this->buildSummaryWithDestination('9');

        self::assertSame('*', $summary->maskedDestination);
    }

    /**
     * The JSON shape of a used, preferred factor carries its last use as ISO
     * 8601.
     *
     * @return void
     */
    public function testJsonSerializeShapeWithLastUse(): void
    {
        $lastUsedAt = Carbon::parse(self::LAST_USED_AT_ISO);

        $summary = new FactorSummary(
            id: '01H',
            type: 'email',
            label: 'Primary',
            maskedDestination: self::SAMPLE_MASKED_EMAIL,
            status: FactorStatus::CONFIRMED,
            preferred: true,
            lastUsedAt: $lastUsedAt,
        );

        self::assertSame([
            'id'                 => '01H',
            'type'               => 'email',
            'label'              => 'Primary',
            'masked_destination' => self::SAMPLE_MASKED_EMAIL,
            'status'             => 'confirmed',
            'preferred'          => true,
            'last_used_at'       => self::LAST_USED_AT_ISO,
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
            type         : 'totp',
            label          : null,
            maskedDestination: null,
            status     : FactorStatus::CONFIRMED,
            preferred: false,
            lastUsedAt: null,
        );

        self::assertSame([
            'id'                 => '01H',
            'type'               => 'totp',
            'label'              => null,
            'masked_destination' => null,
            'status'             => 'confirmed',
            'preferred'          => false,
            'last_used_at'       => null,
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
            type         : 'totp',
            label          : null,
            maskedDestination: null,
            status     : FactorStatus::CONFIRMED,
            preferred: false,
            lastUsedAt: null,
        );

        self::assertJsonStringEqualsJsonString(
            '{"id":"01H","type":"totp","label":null,"masked_destination":null,"status":"confirmed","preferred":false,"last_used_at":null}',
            (string) json_encode($summary),
        );
    }
}
