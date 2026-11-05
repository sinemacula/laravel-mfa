<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Codes\SmsCodeText;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Drivers\AbstractCodeDriver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;

/**
 * Tests that every parameter carrying a code, a message holding one, a
 * destination or a recipient on the way to a sender is marked as sensitive, so
 * PHP records none of them in a trace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeMessage::class)]
#[CoversClass(SmsCodeText::class)]
#[CoversClass(MailEmailSender::class)]
#[CoversClass(NullEmailSender::class)]
#[CoversClass(NullSmsSender::class)]
#[CoversClass(FakeEmailSender::class)]
#[CoversClass(FakeSmsSender::class)]
#[CoversClass(EmailDriver::class)]
#[CoversClass(SmsDriver::class)]
#[CoversClass(CodeService::class)]
final class SensitiveDeliveryParametersTest extends TestCase
{
    /**
     * Rows of a method and the parameters of it that carry plaintext.
     *
     * @return iterable<string, array{class-string, string, list<string>}>
     */
    public static function deliveryParameters(): iterable
    {
        yield 'the code message' => [CodeMessage::class, '__construct', ['destination', 'recipient']];
        yield 'the email sender contract' => [EmailSender::class, 'send', ['message']];
        yield 'the SMS sender contract' => [SmsSender::class, 'send', ['message']];
        yield 'the mail sender' => [MailEmailSender::class, 'send', ['message']];
        yield 'the default email sender' => [NullEmailSender::class, 'send', ['message']];
        yield 'the default SMS sender' => [NullSmsSender::class, 'send', ['message']];
        yield 'the SMS wording' => [SmsCodeText::class, 'of', ['message']];
        yield 'the fake email sender' => [FakeEmailSender::class, 'send', ['message']];
        yield 'the fake email sender\'s lookup' => [FakeEmailSender::class, 'sentTo', ['destination']];
        yield 'the fake email sender\'s code lookup' => [FakeEmailSender::class, 'lastCodeTo', ['destination']];
        yield 'the fake SMS sender' => [FakeSmsSender::class, 'send', ['message']];
        yield 'the fake SMS sender\'s lookup' => [FakeSmsSender::class, 'sentTo', ['destination']];
        yield 'the fake SMS sender\'s code lookup' => [FakeSmsSender::class, 'lastCodeTo', ['destination']];
        yield 'a code driver\'s delivery' => [AbstractCodeDriver::class, 'deliver', ['message']];
        yield 'a code driver\'s transport' => [AbstractCodeDriver::class, 'send', ['message']];
        yield 'the email driver\'s transport' => [EmailDriver::class, 'send', ['message']];
        yield 'the SMS driver\'s transport' => [SmsDriver::class, 'send', ['message']];
        yield 'the code service\'s delivery' => [CodeService::class, 'deliver', ['issued', 'identity']];
    }

    /**
     * Each parameter carrying plaintext is marked as sensitive.
     *
     * @param  class-string  $class
     * @param  string  $method
     * @param  list<string>  $parameters
     * @return void
     */
    #[DataProvider('deliveryParameters')]
    public function testThePlaintextParametersAreMarkedSensitive(string $class, string $method, array $parameters): void
    {
        $marked = [];

        foreach ((new \ReflectionMethod($class, $method))->getParameters() as $parameter) {
            if ($parameter->getAttributes(\SensitiveParameter::class) === []) {
                continue;
            }

            $marked[] = $parameter->getName();
        }

        foreach ($parameters as $parameter) {
            self::assertContains($parameter, $marked);
        }
    }
}
