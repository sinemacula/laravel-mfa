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
     * @return void
     */
    public function testIsFinalReadonlyClass(): void
    {
        $reflection = new \ReflectionClass(FactorSummary::class);

        self::assertTrue($reflection->isFinal());
        self::assertTrue($reflection->isReadOnly());
    }

    /**
     * @return void
     */
    public function testSaysWhetherTheFactorIsDisabled(): void
    {
        $disabled = self::createStub(Factor::class);
        $disabled->method('getFactorIdentifier')->willReturn('01H');
        $disabled->method('getType')->willReturn('totp');
        $disabled->method('getStatus')->willReturn(FactorStatus::CONFIRMED);
        $disabled->method('getDisabledAt')->willReturn(Carbon::now());

        $usable = self::createStub(Factor::class);
        $usable->method('getFactorIdentifier')->willReturn('01J');
        $usable->method('getType')->willReturn('totp');
        $usable->method('getStatus')->willReturn(FactorStatus::CONFIRMED);

        self::assertTrue(FactorSummary::fromFactor($disabled)->disabled);
        self::assertTrue(FactorSummary::fromFactor($disabled)->jsonSerialize()['disabled']);
        self::assertFalse(FactorSummary::fromFactor($usable)->disabled);
    }

    /**
     * @return void
     */
    public function testImplementsJsonSerializable(): void
    {
        self::assertInstanceOf(\JsonSerializable::class, $this->buildMinimalSummary());
    }

    /**
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
     * @return void
     */
    public function testMaskingEmailWithShortSingleCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithDestination('a@example.com');

        self::assertSame('a*@example.com', $summary->maskedDestination);
    }

    /**
     * @return void
     */
    public function testMaskingEmailWithTwoCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithDestination('ab@example.com');

        self::assertSame('a*@example.com', $summary->maskedDestination);
    }

    /**
     * `round` or `ceil` of 3/2 would keep two, more than half.
     *
     * @return void
     */
    public function testMaskingEmailWithThreeCharLocalPartKeepsOneCharViaFloor(): void
    {
        $summary = $this->buildSummaryWithDestination('abc@example.com');

        self::assertSame('a**@example.com', $summary->maskedDestination);
    }

    /**
     * @return void
     */
    public function testMaskingEmailWithFourCharLocalPart(): void
    {
        $summary = $this->buildSummaryWithDestination('abcd@example.com');

        self::assertSame('ab**@example.com', $summary->maskedDestination);
    }

    /**
     * `round` or `ceil` of 5/2 would keep three plaintext characters.
     *
     * @return void
     */
    public function testMaskingEmailWithFiveCharLocalPartKeepsTwoCharsViaFloor(): void
    {
        $summary = $this->buildSummaryWithDestination('alice@example.com');

        self::assertSame('al***@example.com', $summary->maskedDestination);
    }

    /**
     * `floor(6/2)` is 3, so a looser cap would expose three plaintext
     * characters.
     *
     * @return void
     */
    public function testMaskingEmailWithSixCharLocalPartKeepsTwoCharsViaMinCap(): void
    {
        $summary = $this->buildSummaryWithDestination('foobar@example.com');

        self::assertSame('fo****@example.com', $summary->maskedDestination);
    }

    /**
     * Only the first `@` splits the local part from the domain.
     *
     * @return void
     */
    public function testMaskingEmailHonorsExplodeLimitOnSecondAtSign(): void
    {
        $summary = $this->buildSummaryWithDestination('alice@inner@example.com');

        self::assertSame('al***@inner@example.com', $summary->maskedDestination);
    }

    /**
     * @return void
     */
    public function testMaskingEmailPreservesDomain(): void
    {
        $summary = $this->buildSummaryWithDestination('alice@sub.example.com');

        self::assertStringEndsWith('@sub.example.com', (string) $summary->maskedDestination);
    }

    /**
     * @return void
     */
    public function testMaskingPhonePreservesLastFourDigits(): void
    {
        $summary = $this->buildSummaryWithDestination('+15551234567');

        self::assertSame('********4567', $summary->maskedDestination);
    }

    /**
     * @return void
     */
    public function testMaskingShortStringsAreFullyMasked(): void
    {
        $summary = $this->buildSummaryWithDestination('1234');

        self::assertSame('****', $summary->maskedDestination);
    }

    /**
     * @return void
     */
    public function testMaskingSingleCharacterDestinationIsFullyMasked(): void
    {
        $summary = $this->buildSummaryWithDestination('9');

        self::assertSame('*', $summary->maskedDestination);
    }

    /**
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
            'disabled'           => false,
        ], $summary->jsonSerialize());
    }

    /**
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
            'disabled'           => false,
        ], $summary->jsonSerialize());
    }

    /**
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
            '{"id":"01H","type":"totp","label":null,"masked_destination":null,"status":"confirmed","preferred":false,"last_used_at":null,"disabled":false}',
            (string) json_encode($summary),
        );
    }
}
