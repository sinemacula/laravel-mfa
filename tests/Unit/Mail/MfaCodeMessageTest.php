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
    public function testEnvelopeHasDefaultSubject(): void
    {
        $message = new MfaCodeMessage('123456', 10);

        $envelope = $message->envelope();

        self::assertInstanceOf(Envelope::class, $envelope);
        self::assertSame('Your verification code', $envelope->subject);
    }

    public function testContentReturnsContentInstance(): void
    {
        $message = new MfaCodeMessage('987654', 5);

        self::assertInstanceOf(Content::class, $message->content());
    }

    public function testHtmlBodyMentionsCodeAndExpiry(): void
    {
        $message = new MfaCodeMessage('CODEX', 15);

        $content = $message->content();
        $html    = (string) $content->htmlString;

        self::assertStringContainsString('CODEX', $html);
        self::assertStringContainsString('15 minute', $html);
    }

    public function testHtmlBodyEscapesCode(): void
    {
        $message = new MfaCodeMessage('<script>', 5);

        $content = $message->content();
        $html    = (string) $content->htmlString;

        self::assertStringNotContainsString('<script>', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
    }

    public function testHtmlBodyMentionsIgnoreWording(): void
    {
        $message = new MfaCodeMessage('SECRET', 7);
        $content = $message->content();
        $html    = (string) $content->htmlString;

        self::assertStringContainsString('SECRET', $html);
        self::assertStringContainsString('7 minute', $html);
        self::assertStringContainsString('ignore this message', $html);
    }

    public function testHtmlBodyRendererProducesExpectedOutput(): void
    {
        $message    = new MfaCodeMessage('ABC123', 3);
        $reflection = new \ReflectionMethod($message, 'renderHtml');

        /** @var string $html */
        $html = $reflection->invoke($message);

        self::assertStringContainsString('ABC123', $html);
        self::assertStringContainsString('3 minute', $html);
        self::assertStringContainsString('<p>', $html);
    }

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

    public function testExposesCodeAndExpiryAsPublicReadonlyProperties(): void
    {
        $message = new MfaCodeMessage('ABC123', 12);

        self::assertSame('ABC123', $message->code);
        self::assertSame(12, $message->expiresInMinutes);

        $reflection = new \ReflectionClass(MfaCodeMessage::class);
        $codeProp   = $reflection->getProperty('code');
        $expiryProp = $reflection->getProperty('expiresInMinutes');

        self::assertTrue($codeProp->isPublic());
        self::assertTrue($codeProp->isReadOnly());
        self::assertTrue($expiryProp->isPublic());
        self::assertTrue($expiryProp->isReadOnly());
    }
}
