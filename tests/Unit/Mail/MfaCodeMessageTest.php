<?php

declare(strict_types = 1);

namespace Tests\Unit\Mail;

use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Mail\MfaCodeMessage;

/**
 * Unit tests for the default `MfaCodeMessage` mailable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaCodeMessageTest extends TestCase
{
    /**
     * Test envelope has default subject.
     *
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
     * Test content returns content instance.
     *
     * @return void
     */
    public function testContentReturnsContentInstance(): void
    {
        $message = new MfaCodeMessage('987654', 5);

        self::assertInstanceOf(Content::class, $message->content());
    }

    /**
     * Test html body mentions code and expiry.
     *
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
     * Test html body escapes code.
     *
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
     * Test html body mentions ignore wording.
     *
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
     * Test html body wraps content in paragraph tags.
     *
     * @return void
     */
    public function testHtmlBodyWrapsContentInParagraphTags(): void
    {
        $message = new MfaCodeMessage('ABC123', 3);

        $html = (string) $message->content()->htmlString;

        self::assertStringContainsString('<p>', $html);
    }

    /**
     * Test code parameter is marked sensitive.
     *
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
     * Test code property exposes constructor argument.
     *
     * @return void
     */
    public function testCodePropertyExposesConstructorArgument(): void
    {
        $message = new MfaCodeMessage('ABC123', 12);

        self::assertSame('ABC123', $message->code);
    }

    /**
     * Test expiry property exposes constructor argument.
     *
     * @return void
     */
    public function testExpiryPropertyExposesConstructorArgument(): void
    {
        $message = new MfaCodeMessage('ABC123', 12);

        self::assertSame(12, $message->expiresInMinutes);
    }

    /**
     * Test code property is declared public readonly.
     *
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
     * Test expiry property is declared public readonly.
     *
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
