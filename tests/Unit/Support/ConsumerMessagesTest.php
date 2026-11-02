<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Support\ConsumerMessages;
use Tests\TestCase;

/**
 * The wording a consumer can see: the translation of the current locale, or the
 * shipped English whenever the translator has nothing usable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConsumerMessages::class)]
final class ConsumerMessagesTest extends TestCase
{
    /** @var string The English of the plain line the tests read. */
    private const string SUBJECT = 'Your verification code';

    /** @var string The English of the code line the tests read. */
    private const string SMS = 'Your verification code is: :code';

    /**
     * Every shipped key has its constant, and every constant its shipped key,
     * so the file is the one source of the wording.
     *
     * @return void
     */
    public function testEveryShippedKeyHasItsConstantAndTheReverse(): void
    {
        $constants = (new \ReflectionClass(ConsumerMessages::class))->getConstants(\ReflectionClassConstant::IS_PUBLIC);

        unset($constants['CODE_PLACEHOLDER']);

        $shipped = require __DIR__ . '/../../../lang/en/messages.php';

        self::assertIsArray($shipped);
        self::assertEqualsCanonicalizing(
            array_map(static fn (int|string $key): string => 'mfa::messages.' . $key, array_keys($shipped)),
            array_values($constants),
        );

        foreach ($constants as $name => $key) {
            self::assertIsString($key);
            self::assertSame('mfa::messages.' . strtolower($name), $key);
        }
    }

    /**
     * The English is what the shipped file says, however many times it is read.
     *
     * @return void
     */
    public function testTheEnglishIsWhatTheShippedFileSays(): void
    {
        self::assertSame('Further authentication is required.', ConsumerMessages::english(ConsumerMessages::FURTHER_AUTHENTICATION_REQUIRED));
        self::assertSame(self::SMS, ConsumerMessages::english(ConsumerMessages::SMS_CODE));
        self::assertSame(self::SUBJECT, ConsumerMessages::english(ConsumerMessages::EMAIL_SUBJECT));
        self::assertSame(self::SMS, ConsumerMessages::english(ConsumerMessages::EMAIL_CODE));
        self::assertSame('This code expires in :minutes minute.|This code expires in :minutes minutes.', ConsumerMessages::english(ConsumerMessages::EMAIL_EXPIRY));
        self::assertSame('If you did not request this code, you can safely ignore this message.', ConsumerMessages::english(ConsumerMessages::EMAIL_IGNORE));
    }

    /**
     * An application's override of `en` is honoured by the translator and never
     * reaches the shipped English.
     *
     * @return void
     */
    public function testTheEnglishIgnoresAnOverride(): void
    {
        $this->lines('en', ['email_subject' => 'Overridden']);

        self::assertSame('Overridden', ConsumerMessages::line(ConsumerMessages::EMAIL_SUBJECT));
        self::assertSame(self::SUBJECT, ConsumerMessages::english(ConsumerMessages::EMAIL_SUBJECT));
    }

    /**
     * The shipped translations are loaded for the package's namespace.
     *
     * @return void
     */
    public function testTheShippedLinesAreLoaded(): void
    {
        self::assertSame(self::SUBJECT, __(ConsumerMessages::EMAIL_SUBJECT));
    }

    /**
     * A line of the current locale is what is said, and it follows the locale
     * from one call to the next: neither the translator nor its locale is kept.
     *
     * @return void
     */
    public function testTheLineFollowsTheLocaleBetweenCalls(): void
    {
        $this->lines('fr', ['email_subject' => 'Votre code']);
        $this->lines('de', ['email_subject' => 'Ihr Code']);

        self::assertSame(self::SUBJECT, ConsumerMessages::line(ConsumerMessages::EMAIL_SUBJECT));
        self::assertSame('en', ConsumerMessages::locale());

        app()->setLocale('fr');

        self::assertSame('Votre code', ConsumerMessages::line(ConsumerMessages::EMAIL_SUBJECT));
        self::assertSame('fr', ConsumerMessages::locale());

        app()->setLocale('de');

        self::assertSame('Ihr Code', ConsumerMessages::line(ConsumerMessages::EMAIL_SUBJECT));
        self::assertSame('de', ConsumerMessages::locale());
    }

    /**
     * An untranslated locale whose fallback is not English gets the shipped
     * English, where the translator alone would end at the key.
     *
     * @return void
     */
    public function testAnUntranslatedLocaleWithANonEnglishFallbackGetsTheEnglish(): void
    {
        app()->setLocale('fr');
        app('translator')->setFallback('de');

        self::assertSame(self::SUBJECT, ConsumerMessages::line(ConsumerMessages::EMAIL_SUBJECT));
        self::assertSame('This code expires in 1 minute.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 1));
        self::assertSame(self::SMS, ConsumerMessages::codeLine(ConsumerMessages::SMS_CODE));
    }

    /**
     * A valid translation in a non-English fallback locale is honoured before
     * the shipped English.
     *
     * @return void
     */
    public function testATranslationInTheFallbackLocaleIsHonouredFirst(): void
    {
        app()->setLocale('fr');
        app('translator')->setFallback('de');

        $this->lines('de', ['email_subject' => 'Ihr Code', 'sms_code' => 'Code :code', 'email_expiry' => ':minutes Minute.|:minutes Minuten.']);

        self::assertSame('Ihr Code', ConsumerMessages::line(ConsumerMessages::EMAIL_SUBJECT));
        self::assertSame('Code :code', ConsumerMessages::codeLine(ConsumerMessages::SMS_CODE));
        self::assertSame('5 Minuten.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 5));
    }

    /**
     * The answers that cannot be said.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function unusableAnswers(): iterable
    {
        yield 'empty' => [''];
        yield 'whitespace' => [" \t\n"];
        yield 'an array' => [['nested' => 'value']];
    }

    /**
     * An unusable answer is replaced by the shipped English, on the plain, the
     * code and the plural path.
     *
     * @param  mixed  $answer
     * @return void
     */
    #[DataProvider('unusableAnswers')]
    public function testAnUnusableAnswerGivesTheEnglish(mixed $answer): void
    {
        app()->setLocale('fr');

        $this->lines('fr', ['email_subject' => $answer, 'sms_code' => $answer, 'email_expiry' => $answer]);

        self::assertSame(self::SUBJECT, ConsumerMessages::line(ConsumerMessages::EMAIL_SUBJECT));
        self::assertSame(self::SMS, ConsumerMessages::codeLine(ConsumerMessages::SMS_CODE));
        self::assertSame('This code expires in 1 minute.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 1));
        self::assertSame('This code expires in 5 minutes.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 5));
    }

    /**
     * Without a translator the line is the shipped English, the locale is
     * unknown, and raising a refusal never raises something else.
     *
     * @return void
     */
    public function testWithoutATranslatorTheLineIsTheEnglish(): void
    {
        $container = Container::getInstance();

        Container::setInstance(new Container);

        try {
            self::assertSame(self::SUBJECT, ConsumerMessages::line(ConsumerMessages::EMAIL_SUBJECT));
            self::assertSame(self::SMS, ConsumerMessages::codeLine(ConsumerMessages::SMS_CODE));
            self::assertSame('This code expires in 1 minute.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 1));
            self::assertSame('This code expires in 5 minutes.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 5));
            self::assertNull(ConsumerMessages::locale());
        } finally {
            Container::setInstance($container);
        }
    }

    /**
     * A code line must carry the exact placeholder: one without it, or with it
     * in another case, is replaced by the shipped English, and it is returned
     * as the template, with no code in it.
     *
     * @return void
     */
    public function testACodeLineMustCarryTheExactPlaceholder(): void
    {
        app()->setLocale('fr');

        $this->lines('fr', ['sms_code' => 'Votre code est :code']);

        self::assertSame('Votre code est :code', ConsumerMessages::codeLine(ConsumerMessages::SMS_CODE));

        foreach (['Votre code est prêt', 'Votre code est :Code', 'Votre code est :CODE'] as $line) {
            $this->lines('fr', ['sms_code' => $line]);

            self::assertSame(self::SMS, ConsumerMessages::codeLine(ConsumerMessages::SMS_CODE), $line);
        }
    }

    /**
     * A plural line selects by the locale's rules, with the minutes replaced.
     *
     * @return void
     */
    public function testAPluralLineSelectsByTheLocale(): void
    {
        self::assertSame('This code expires in 1 minute.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 1));
        self::assertSame('This code expires in 2 minutes.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 2));

        app()->setLocale('fr');

        $this->lines('fr', ['email_expiry' => 'Expire dans :minutes minute.|Expire dans :minutes minutes.']);

        self::assertSame('Expire dans 1 minute.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 1));
        self::assertSame('Expire dans 2 minutes.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 2));
    }

    /**
     * The English fallback uses English plural rules whatever the locale, whose
     * own would call 0 and 1 singular or have more forms.
     *
     * @return void
     */
    public function testTheEnglishFallbackUsesEnglishPluralRules(): void
    {
        app()->setLocale('fr');

        self::assertSame('This code expires in 1 minute.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 1));
        self::assertSame('This code expires in 0 minutes.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 0));
        self::assertSame('This code expires in 21 minutes.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 21));
    }

    /**
     * A line that passes the first look and selects an empty branch falls back:
     * the selected answer is checked too.
     *
     * @return void
     */
    public function testAnEmptySelectedBranchGivesTheEnglish(): void
    {
        app()->setLocale('fr');

        $this->lines('fr', ['email_expiry' => 'Une minute|']);

        self::assertSame('Une minute', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 1));
        self::assertSame('This code expires in 5 minutes.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 5));
    }

    /**
     * A plural line without the minutes is still a usable answer.
     *
     * @return void
     */
    public function testAPluralLineWithoutTheMinutesIsUsable(): void
    {
        app()->setLocale('fr');

        $this->lines('fr', ['email_expiry' => 'Bientôt expiré.']);

        self::assertSame('Bientôt expiré.', ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, 5));
    }

    /**
     * Add lines to the package's messages in the locale.
     *
     * @param  string  $locale
     * @param  array<string, mixed>  $lines
     * @return void
     */
    private function lines(string $locale, array $lines): void
    {
        $keyed = [];

        foreach ($lines as $key => $line) {
            $keyed['messages.' . $key] = $line;
        }

        // @phpstan-ignore argument.type
        app('translator')->addLines($keyed, $locale, 'mfa');
    }
}
