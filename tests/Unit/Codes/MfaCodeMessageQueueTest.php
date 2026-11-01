<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Mail\SendQueuedMailable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use Tests\Fixtures\Codes\CustomMfaCodeMessage;
use Tests\Fixtures\Codes\PayloadRecordingQueue;
use Tests\TestCase;

/**
 * Tests that `MfaCodeMessage` is never queued in clear: the payload a queue
 * stores for it holds the code only encrypted with the application key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaCodeMessage::class)]
final class MfaCodeMessageQueueTest extends TestCase
{
    /** @var string A code no payload may hold in clear. */
    private const string CODE = '493817';

    /**
     * The message, and a subclass of it, asks to be encrypted on the queue.
     *
     * @return void
     */
    public function testTheMessageAsksToBeEncryptedOnTheQueue(): void
    {
        self::assertInstanceOf(ShouldBeEncrypted::class, new MfaCodeMessage(self::CODE, 10));
        self::assertTrue((new SendQueuedMailable(new MfaCodeMessage(self::CODE, 10)))->shouldBeEncrypted);
        self::assertTrue((new SendQueuedMailable(new CustomMfaCodeMessage(self::CODE, 10)))->shouldBeEncrypted);
    }

    /**
     * The payload a queue stores for the queued message holds no plaintext
     * code, and decrypts to the message with its code.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAQueuedMessageHoldsNoPlaintextCode(): void
    {
        $queue = new PayloadRecordingQueue;
        $queue->setContainer($this->container());

        $payload = $queue->payloadFor(new SendQueuedMailable(new MfaCodeMessage(self::CODE, 10)));

        self::assertStringNotContainsString(self::CODE, $payload);

        $decoded = json_decode($payload, true);

        self::assertIsArray($decoded);

        $data = $decoded['data'] ?? null;

        self::assertIsArray($data);

        $command = $data['command'] ?? null;

        self::assertIsString($command);
        self::assertStringNotContainsString('MfaCodeMessage', $command);

        $serialized = $this->container()->make(Encrypter::class)->decrypt($command);

        self::assertIsString($serialized);

        $job = unserialize($serialized);

        self::assertInstanceOf(SendQueuedMailable::class, $job);
        self::assertInstanceOf(MfaCodeMessage::class, $job->mailable);
        self::assertSame(self::CODE, $job->mailable->code);
    }
}
