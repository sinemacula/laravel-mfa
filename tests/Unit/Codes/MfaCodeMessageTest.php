<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaCodeMessage::class)]
final class MfaCodeMessageTest extends TestCase
{
    /**
     * @return void
     */
    public function testEnvelopeHasDefaultSubject(): void
    {
        $message = new MfaCodeMessage('123456', 10);

        $envelope = $message->envelope();

        self::assertInstanceOf(Envelope::class, $envelope);
        self::assertSame('Your verification code', $envelope->subject);
    }

    /**
     * @return void
     */
    public function testContentReturnsContentInstance(): void
    {
        $message = new MfaCodeMessage('987654', 5);

        self::assertInstanceOf(Content::class, $message->content());
    }

    /**
     * @return void
     */
    public function testHtmlBodyMentionsCodeAndExpiry(): void
    {
        $message = new MfaCodeMessage('CODEX', 15);

        $content = $message->content();
        $html    = (string) $content->htmlString;

        self::assertStringContainsString('CODEX', $html);
        self::assertStringContainsString('15 minute', $html);
    }

    /**
     * @return void
     */
    public function testHtmlBodyEscapesCode(): void
    {
        $message = new MfaCodeMessage('<script>', 5);

        $content = $message->content();
        $html    = (string) $content->htmlString;

        self::assertStringNotContainsString('<script>', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
    }

    /**
     * @return void
     */
    public function testHtmlBodyMentionsIgnoreWording(): void
    {
        $message = new MfaCodeMessage('SECRET', 7);
        $content = $message->content();
        $html    = (string) $content->htmlString;

        self::assertStringContainsString('SECRET', $html);
        self::assertStringContainsString('7 minute', $html);
        self::assertStringContainsString('ignore this message', $html);
    }

    /**
     * @return void
     */
    public function testHtmlBodyWrapsContentInParagraphTags(): void
    {
        $message = new MfaCodeMessage('ABC123', 3);

        $html = (string) $message->content()->htmlString;

        self::assertStringContainsString('<p>', $html);
    }

    /**
     * The three shipped English lines, only the package's tags as markup, and
     * the singular for one minute.
     *
     * @return void
     */
    public function testTheBodyIsTheShippedLines(): void
    {
        $ignore = 'If you did not request this code, you can safely ignore this message.';

        self::assertSame(
            '<p>Your verification code is: <strong>ABC123</strong></p><p>This code expires in 3 minutes.</p><p>' . $ignore . '</p>',
            (string) (new MfaCodeMessage('ABC123', 3))->content()->htmlString,
        );

        self::assertSame(
            '<p>Your verification code is: <strong>ABC123</strong></p><p>This code expires in 1 minute.</p><p>' . $ignore . '</p>',
            (string) (new MfaCodeMessage('ABC123', 1))->content()->htmlString,
        );
    }

    /**
     * Quotes are escaped as HTML5 writes them, and invalid UTF-8 is replaced
     * rather than emptying the line.
     *
     * @return void
     */
    public function testEscapingCoversQuotesAndInvalidUtf8(): void
    {
        $html = (string) (new MfaCodeMessage("&\"'\xFF", 3))->content()->htmlString;

        self::assertStringContainsString("<strong>&amp;&quot;&apos;\u{FFFD}</strong>", $html);
    }

    /**
     * @return void
     */
    public function testASubclassCanOverrideTheBody(): void
    {
        $message = new class ('ABC123', 3) extends MfaCodeMessage {
            /**
             * @return string
             */
            #[\Override]
            protected function renderHtml(): string
            {
                return '<p>Branded</p>';
            }
        };

        self::assertSame('<p>Branded</p>', $message->content()->htmlString);
    }

    /**
     * @return void
     */
    public function testCodeParameterIsMarkedSensitive(): void
    {
        $reflection = new \ReflectionMethod(MfaCodeMessage::class, '__construct');

        $codeParam = null;

        foreach ($reflection->getParameters() as $parameter) {
            if ($parameter->getName() === 'code') {
                $codeParam = $parameter;
                break;
            }
        }

        self::assertNotNull($codeParam);
        self::assertNotEmpty($codeParam->getAttributes(\SensitiveParameter::class));
    }

    /**
     * @return void
     */
    public function testCodePropertyExposesConstructorArgument(): void
    {
        $message = new MfaCodeMessage('ABC123', 12);

        self::assertSame('ABC123', $message->code);
    }

    /**
     * @return void
     */
    public function testExpiryPropertyExposesConstructorArgument(): void
    {
        $message = new MfaCodeMessage('ABC123', 12);

        self::assertSame(12, $message->expiresInMinutes);
    }

    /**
     * @return void
     */
    public function testCodePropertyIsDeclaredPublicReadonly(): void
    {
        $reflection = new \ReflectionClass(MfaCodeMessage::class);
        $property   = $reflection->getProperty('code');

        self::assertTrue($property->isPublic());
        self::assertTrue($property->isReadOnly());
    }

    /**
     * @return void
     */
    public function testExpiryPropertyIsDeclaredPublicReadonly(): void
    {
        $reflection = new \ReflectionClass(MfaCodeMessage::class);
        $property   = $reflection->getProperty('expiresInMinutes');

        self::assertTrue($property->isPublic());
        self::assertTrue($property->isReadOnly());
    }
}
