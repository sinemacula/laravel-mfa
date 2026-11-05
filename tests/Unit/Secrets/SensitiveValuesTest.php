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
 * Tests for `SensitiveValues`: a value known to be sensitive is redacted from
 * any string containing it, whatever its length; a value collected only from a
 * string that is it, or contains it when it is six characters or more; and the
 * values are collected from a trace's arguments, a log's values and code
 * messages, and from nothing else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SensitiveValues::class)]
final class SensitiveValuesTest extends TestCase
{
    /**
     * A value known to be sensitive matches any string containing it, however
     * short it is, and every occurrence of it leaves a text.
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
     * A value collected matches a string that is it, or contains it when it is
     * six characters or more; a shorter one leaves a text only when the text is
     * it.
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
     * Each occurrence is replaced once, the longest value first, and a marker
     * put in is never searched again.
     *
     * @return void
     */
    public function testRedactsTheLongestValueFirstAndOnlyOnce(): void
    {
        $values = SensitiveValues::known('4821', 'redacted', '48211234');

        self::assertSame('[redacted] and [redacted]', $values->redactIn('48211234 and 4821'));
    }

    /**
     * Empty values, missing values and the redaction marker are never values to
     * redact.
     *
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
     * A frame that does not touch the package gives only the values marked as
     * sensitive and those under a key naming a secret, a code or a
     * destination; one that does gives every string.
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
     * A code message, or a queued job sending one, nested in an array too,
     * gives its code and its recipients' addresses as known values; a job
     * sending another message gives nothing.
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
     * A code message handed to a sender, nested in an array too, gives its code
     * and its destination as known values.
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
     * Every recipient of every kind is read, and only a queued job sending a
     * code message counts as one: not a job sending another message, nor any
     * other object holding a code message.
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
     * A log's values give no plain string unless a key naming a secret, a code
     * or a destination holds it, and values nested deeper than ten levels,
     * inside a sensitive or a secret value too, are not collected.
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
     * Combining values keeps both sides' values of each kind.
     *
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
     * A recipient without a string address gives nothing.
     *
     * @return void
     */
    public function testSkipsARecipientWithoutAnAddress(): void
    {
        $message     = new MfaCodeMessage('4821', 10);
        $message->to = [['name' => 'Ada'], 'ada@example.test', ['address' => 42]];

        self::assertSame(['4821'], SensitiveValues::ofCodeMessage($message));
    }

    /**
     * A log's values give what an exception among them recorded in its trace,
     * besides what a trace's arguments give; a trace's arguments do not read an
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
     * Values nested deeper than ten levels are not collected.
     *
     * @return void
     */
    public function testStopsCollectingAtTheDeepestLevel(): void
    {
        self::assertTrue(SensitiveValues::inArguments($this->nested('shallow-value', 10), true)->matches('shallow-value'));
        self::assertFalse(SensitiveValues::inArguments($this->nested('deep-value', 11), true)->matches('deep-value'));
    }

    /**
     * Values combined keep their kind: a known value still matches whatever its
     * length, and a collected one does not.
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
     * The value, nested in as many lists.
     *
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
