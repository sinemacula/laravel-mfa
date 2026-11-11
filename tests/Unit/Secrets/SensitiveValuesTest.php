<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Mail\Mailable;
use Illuminate\Mail\SendQueuedMailable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Secrets\SensitiveValues;
use Tests\Fixtures\Codes\CodeMessages;
use Tests\Fixtures\Secrets\ForgedTrace;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SensitiveValues::class)]
final class SensitiveValuesTest extends TestCase
{
    /**
     * However short, and every occurrence leaves the text.
     *
     * @return void
     */
    public function testAKnownValueIsRedactedWhateverItsLength(): void
    {
        $values = SensitiveValues::known('4821');

        self::assertTrue($values->matches('Your code is 4821'));
        self::assertTrue($values->matches('4821'));
        self::assertFalse($values->matches('Your code is 4822'));
        self::assertSame('Code [redacted], again [redacted].', $values->redactIn('Code 4821, again 4821.'));
    }

    /**
     * A shorter one leaves a text only when the text is it.
     *
     * @return void
     */
    public function testACollectedValueIsRedactedWhenEqualOrLongEnough(): void
    {
        $values = SensitiveValues::inArguments(['sms', '482915'], true);

        self::assertTrue($values->matches('sms'));
        self::assertFalse($values->matches('an sms reminder'));
        self::assertTrue($values->matches('code 482915 sent'));
        self::assertFalse($values->matches('code 48291 sent'));
        self::assertSame('an sms reminder for [redacted]', $values->redactIn('an sms reminder for 482915'));
        self::assertSame('[redacted]', $values->redactIn('sms'));
        self::assertSame('kept', $values->redactIn('kept'));
    }

    /**
     * A marker put in is never searched again.
     *
     * @return void
     */
    public function testRedactsTheLongestValueFirstAndOnlyOnce(): void
    {
        $values = SensitiveValues::known('4821', 'redacted', '48211234');

        self::assertSame('[redacted] and [redacted]', $values->redactIn('48211234 and 4821'));
    }

    /**
     * @return void
     */
    public function testIgnoresEmptyValuesAndTheMarker(): void
    {
        $values = SensitiveValues::known('', null, '[redacted]')->with(SensitiveValues::inArguments(['', '[redacted]'], true));

        self::assertFalse($values->matches(''));
        self::assertFalse($values->matches('[redacted]'));
        self::assertSame('kept [redacted]', $values->redactIn('kept [redacted]'));
        self::assertFalse(SensitiveValues::none()->matches('anything'));
    }

    /**
     * An outside frame gives only values marked sensitive or under a sensitive
     * key; a package frame gives every string.
     *
     * @return void
     */
    public function testCollectsFromATracesArguments(): void
    {
        $arguments = [
            'harmless',
            ['to' => 'ada@example.test', 'label' => 'Phone'],
            new \SensitiveParameterValue('marked-value'),
            new RevealedSecret('revealed-value'),
            (object) ['code' => 'object-value'],
            42,
        ];

        $other = SensitiveValues::inArguments($arguments, false);
        $all   = SensitiveValues::inArguments($arguments, true);

        self::assertFalse($other->matches('harmless'));
        self::assertFalse($other->matches('Phone'));
        self::assertTrue($other->matches('ada@example.test'));
        self::assertTrue($other->matches('marked-value'));
        self::assertTrue($other->matches('revealed-value'));
        self::assertFalse($other->matches('object-value'));
        self::assertTrue($all->matches('harmless'));
        self::assertTrue($all->matches('Phone'));
    }

    /**
     * Nested or queued too; a job sending another message gives nothing.
     *
     * @return void
     */
    public function testCollectsTheCodeAndRecipientsOfACodeMessage(): void
    {
        $message = (new MfaCodeMessage('4821', 10))->to('ada@example.test')->cc('cc@example.test')->bcc('bcc@example.test');

        $values = SensitiveValues::inArguments([[new SendQueuedMailable($message)]], false);

        self::assertTrue($values->matches('Your code is 4821'));
        self::assertTrue($values->matches('<ada@example.test>'));
        self::assertTrue($values->matches('cc@example.test'));
        self::assertTrue($values->matches('bcc@example.test'));
        self::assertSame(['4821', 'ada@example.test', 'cc@example.test', 'bcc@example.test'], SensitiveValues::ofCodeMessage($message));
        self::assertTrue(SensitiveValues::isCodeMessage($message));
        self::assertFalse(SensitiveValues::isCodeMessage(new SendQueuedMailable(new Mailable)));
        self::assertFalse(SensitiveValues::isCodeMessage('4821'));
    }

    /**
     * Nested in an array too.
     *
     * @return void
     */
    public function testCollectsTheCodeAndDestinationOfASendersMessage(): void
    {
        $message = CodeMessages::to('ada@example.test', '4821');

        $values = SensitiveValues::inArguments([[$message]], false);

        self::assertTrue($values->matches('Your code is 4821'));
        self::assertTrue($values->matches('<ada@example.test>'));
        self::assertSame(['4821', 'ada@example.test'], SensitiveValues::ofCodeMessage($message));
        self::assertTrue(SensitiveValues::isCodeMessage($message));
    }

    /**
     * Not a job sending another message, nor any other object holding a code
     * message.
     *
     * @return void
     */
    public function testReadsEveryRecipientAndOnlyAJobSendingACodeMessage(): void
    {
        $message = (new MfaCodeMessage('4821', 10))
            ->to(['to-1@example.test', 'to-2@example.test'])
            ->cc(['cc-1@example.test', 'cc-2@example.test'])
            ->bcc(['bcc-1@example.test', 'bcc-2@example.test']);

        self::assertSame(
            ['4821', 'to-1@example.test', 'to-2@example.test', 'cc-1@example.test', 'cc-2@example.test', 'bcc-1@example.test', 'bcc-2@example.test'],
            SensitiveValues::ofCodeMessage($message),
        );

        $holder = new class {
            /** @var mixed A message the object holds. */
            public mixed $mailable = null;
        };
        $holder->mailable = $message;

        self::assertFalse(SensitiveValues::isCodeMessage($holder));
        self::assertFalse(SensitiveValues::isCodeMessage(new SendQueuedMailable(new Mailable)));
        self::assertTrue(SensitiveValues::isCodeMessage(new SendQueuedMailable($message)));
        self::assertFalse(SensitiveValues::inArguments([new SendQueuedMailable(new Mailable)], false)->matches('anything'));
    }

    /**
     * Only under a sensitive key, and nothing deeper than ten levels, even
     * inside a sensitive or secret value.
     *
     * @return void
     */
    public function testCollectsFromALogsValuesWithinTheBounds(): void
    {
        self::assertFalse(SensitiveValues::inLogValues(['note' => 'harmless-text'])->matches('harmless-text'));
        self::assertTrue(SensitiveValues::inLogValues($this->nested(new \SensitiveParameterValue('shallow-value'), 9))->matches('shallow-value'));
        self::assertFalse(SensitiveValues::inLogValues($this->nested(new \SensitiveParameterValue('deep-value'), 10))->matches('deep-value'));
        self::assertTrue(SensitiveValues::inArguments($this->nested(new RevealedSecret('shallow-value'), 9), false)->matches('shallow-value'));
        self::assertFalse(SensitiveValues::inArguments($this->nested(new RevealedSecret('deep-value'), 10), false)->matches('deep-value'));
    }

    /**
     * @return void
     */
    public function testCombiningKeepsBothSides(): void
    {
        $values = SensitiveValues::known('left-known')->with(SensitiveValues::known('right-known'));

        self::assertTrue($values->matches('left-known'));
        self::assertTrue($values->matches('right-known'));

        $values = SensitiveValues::inArguments(['left-collected'], true)->with(SensitiveValues::inArguments(['right-collected'], true));

        self::assertTrue($values->matches('left-collected'));
        self::assertTrue($values->matches('right-collected'));
    }

    /**
     * @return void
     */
    public function testSkipsARecipientWithoutAnAddress(): void
    {
        $message     = new MfaCodeMessage('4821', 10);
        $message->to = [['name' => 'Ada'], 'ada@example.test', ['address' => 42]];

        self::assertSame(['4821'], SensitiveValues::ofCodeMessage($message));
    }

    /**
     * Besides what a trace's arguments give; a trace's arguments do not read an
     * exception.
     *
     * @return void
     */
    public function testCollectsWhatALoggedExceptionRecorded(): void
    {
        $exception = ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            ['file' => '/app/Http/Controllers/VerifyController.php', 'line' => 12, 'class' => MfaManager::class, 'type' => '->', 'function' => 'verify', 'args' => ['482915']],
        ]);

        self::assertTrue(SensitiveValues::inLogValues(['exception' => $exception, 'code' => '739104'])->matches('482915'));
        self::assertTrue(SensitiveValues::inLogValues(['exception' => $exception, 'code' => '739104'])->matches('739104'));
        self::assertFalse(SensitiveValues::inArguments([$exception], false)->matches('482915'));
    }

    /**
     * Ten levels.
     *
     * @return void
     */
    public function testStopsCollectingAtTheDeepestLevel(): void
    {
        self::assertTrue(SensitiveValues::inArguments($this->nested('shallow-value', 10), true)->matches('shallow-value'));
        self::assertFalse(SensitiveValues::inArguments($this->nested('deep-value', 11), true)->matches('deep-value'));
    }

    /**
     * A known value still matches whatever its length, and a collected one does
     * not.
     *
     * @return void
     */
    public function testCombinedValuesKeepTheirKind(): void
    {
        $values = SensitiveValues::inArguments(['abcd'], true)->with(SensitiveValues::known('wxyz'));

        self::assertFalse($values->matches('abcde'));
        self::assertTrue($values->matches('wxyz1'));
        self::assertSame('abcde [redacted]1', $values->redactIn('abcde wxyz1'));
    }

    /**
     * @param  mixed  $value
     * @param  int  $levels
     * @return array<int, mixed>
     */
    private function nested(mixed $value, int $levels): array
    {
        $nested = [$value];

        for ($level = 1; $level < $levels; $level++) {
            $nested = [$nested];
        }

        return $nested;
    }
}
