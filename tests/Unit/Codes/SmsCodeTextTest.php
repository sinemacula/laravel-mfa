<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\SmsCodeText;
use Tests\Fixtures\Codes\CodeMessages;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SmsCodeText::class)]
final class SmsCodeTextTest extends TestCase
{
    /**
     * @return void
     */
    public function testTheShippedEnglishCarriesTheCode(): void
    {
        self::assertSame('Your verification code is: 482915', SmsCodeText::of(CodeMessages::to('+447700900123', '482915', type: 'sms')));
    }

    /**
     * @return void
     */
    public function testTheLineIsInTheCurrentLocale(): void
    {
        app('translator')->addLines(['messages.sms_code' => 'Votre code : :code'], 'fr', 'mfa');
        app()->setLocale('fr');

        self::assertSame('Votre code : 482915', SmsCodeText::of(CodeMessages::to('+447700900123', '482915', type: 'sms')));
    }

    /**
     * So the code is never left out.
     *
     * @return void
     */
    public function testALineLosingTheCodeGivesTheEnglish(): void
    {
        app('translator')->addLines(['messages.sms_code' => 'Votre code est prêt.'], 'fr', 'mfa');
        app()->setLocale('fr');

        self::assertSame('Your verification code is: 482915', SmsCodeText::of(CodeMessages::to('+447700900123', '482915', type: 'sms')));
    }
}
