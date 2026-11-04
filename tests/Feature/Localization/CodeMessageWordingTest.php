<?php

declare(strict_types = 1);

namespace Tests\Feature\Localization;

use Carbon\Carbon;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Mail\SendQueuedMailable;
use Illuminate\Mail\Transport\ArrayTransport;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Testing\Fakes\MailFake;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Codes\SmsCodeText;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Support\ConsumerMessages;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mime\Email;
use Tests\Fixtures\Codes\CodeMessages;
use Tests\Fixtures\Codes\PayloadRecordingQueue;
use Tests\Fixtures\Codes\WordingSmsSender;
use Tests\Fixtures\Testing\ChooseLocale;
use Tests\Fixtures\Testing\ExplicitLocaleCodeMessage;
use Tests\Fixtures\Testing\RecordingTranslator;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * The email and the SMS a code is sent in, in the words of the locale it is
 * sent from, through the kernel and through a queue, with the code reaching
 * neither the translator nor any markup a translation could write.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConsumerMessages::class)]
#[CoversClass(MailEmailSender::class)]
#[CoversClass(MfaCodeMessage::class)]
#[CoversClass(SmsCodeText::class)]
final class CodeMessageWordingTest extends TestCase
{
    use ArrangesVerification;

    /** @var string The phone number the SMS factor delivers to. */
    private const string PHONE = '+447700900123';

    /** @var array<string, string> The lines in French. */
    private const array FRENCH = [
        'messages.sms_code'      => 'Votre code par SMS : :code',
        'messages.email_subject' => 'Votre code de vérification',
        'messages.email_code'    => 'Votre code est : :code',
        'messages.email_expiry'  => 'Ce code expire dans :minutes minute.|Ce code expire dans :minutes minutes.',
        'messages.email_ignore'  => 'Si vous n\'avez rien demandé, ignorez ce message.',
    ];

    /** @var \Tests\Fixtures\Codes\WordingSmsSender The SMS sender, wording each code as the package does. */
    private WordingSmsSender $texts;

    /** @var \Illuminate\Support\Testing\Fakes\MailFake The mail the package's mail sender sent. */
    private MailFake $outbox;

    /**
     * Arrange the application, with every code type, a mailbox, a phone and the
     * lines in French.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();

        $this->enableApplication(['types' => ['totp', 'email', 'sms']]);

        $this->texts  = new WordingSmsSender;
        $this->outbox = Mail::fake();

        $this->container()->instance(SmsSender::class, $this->texts);
        $this->container()->bind(EmailSender::class, MailEmailSender::class);

        app('translator')->addLines(self::FRENCH, 'fr', 'mfa');
    }

    /**
     * Release the frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A code sent through the kernel in a locale a middleware chose reaches the
     * sender with the message's locale captured, and renders in it: the subject
     * and the whole body, after the request has put its locale back.
     *
     * @return void
     */
    public function testAnEmailSentThroughTheKernelIsInTheRequestsLocale(): void
    {
        $factor = $this->emailFactor($this->signedInPerson());

        $this->postJson('code/' . $factor->id)->assertOk();

        $message = $this->lastMessage();

        self::assertSame('fr', $message->locale);

        app()->setLocale('en');

        $html = $message->render();

        self::assertStringContainsString('Votre code est : <strong>' . $message->code . '</strong>', $html);
        self::assertStringContainsString('Ce code expire dans 10 minutes.', $html);
        self::assertStringContainsString('Si vous n&apos;avez rien demandé, ignorez ce message.', $html);
        self::assertSame('en', app()->getLocale());
    }

    /**
     * Delivered through Laravel's mailer, the message's subject and body are in
     * the locale it was sent in, as Laravel enters that locale before it builds
     * them, and the current locale is put back.
     *
     * @return void
     */
    public function testAnEmailDeliveredThroughTheMailerIsInItsLocale(): void
    {
        config()->set('mail.default', 'array');
        config()->set('mail.mailers.array', ['transport' => 'array']);

        Mail::swap($this->outbox->manager);

        $factor = $this->emailFactor($this->signedInPerson());

        $this->postJson('code/' . $factor->id)->assertOk();

        $transport = Mail::mailer('array')->getSymfonyTransport(); // @phpstan-ignore staticMethod.dynamicCall

        self::assertInstanceOf(ArrayTransport::class, $transport);

        $sent = $transport->messages()->first();

        self::assertInstanceOf(SentMessage::class, $sent);

        $email = $sent->getOriginalMessage();

        self::assertInstanceOf(Email::class, $email);
        self::assertSame('Votre code de vérification', $email->getSubject());
        self::assertStringContainsString('Ce code expire dans 10 minutes.', (string) $email->getHtmlBody());
    }

    /**
     * An SMS sent through the kernel is rendered when it is sent, in the
     * request's locale, with the code in it.
     *
     * @return void
     */
    public function testAnSmsSentThroughTheKernelIsInTheRequestsLocale(): void
    {
        $factor = $this->factorOf($this->signedInPerson(), ['type' => 'sms', 'destination' => self::PHONE]);

        $this->postJson('code/' . $factor->id)->assertOk();

        self::assertMatchesRegularExpression('/^Votre code par SMS : \d{6}$/D', (string) $this->texts->lastTextTo(self::PHONE));
    }

    /**
     * An untranslated locale with a non-English fallback sends the shipped
     * English on both channels.
     *
     * @return void
     */
    public function testAnUntranslatedLocaleSendsTheEnglish(): void
    {
        app('translator')->setFallback('de');
        app()->setLocale('it');

        $user = $this->signedInPerson();

        Mfa::sendCode($this->emailFactor($user)->id);
        Mfa::sendCode($this->factorOf($user, ['type' => 'sms', 'destination' => self::PHONE])->id);

        self::assertMatchesRegularExpression('/^Your verification code is: \d{6}$/D', (string) $this->texts->lastTextTo(self::PHONE));

        $html = $this->lastMessage()->render();

        self::assertStringContainsString('Your verification code is: <strong>', $html);
        self::assertStringContainsString('This code expires in 10 minutes.', $html);
        self::assertStringContainsString('you can safely ignore this message.', $html);
    }

    /**
     * The lines that lose the code.
     *
     * @return iterable<string, array{string}>
     */
    public static function linesLosingTheCode(): iterable
    {
        yield 'no placeholder' => ['Votre code est prêt.'];
        yield 'the placeholder in another case' => ['Votre code est :CODE'];
        yield 'nothing' => [''];
    }

    /**
     * A line that would lose the code delivers the English with the code in it,
     * on both channels: a usable message rather than none, or one with no code.
     *
     * @param  string  $line
     * @return void
     */
    #[DataProvider('linesLosingTheCode')]
    public function testALineLosingTheCodeDeliversTheEnglishWithIt(string $line): void
    {
        $user = $this->signedInPerson();

        app('translator')->addLines(['messages.sms_code' => $line, 'messages.email_code' => $line], 'fr', 'mfa');
        app()->setLocale('fr');

        Mfa::sendCode($this->emailFactor($user)->id);
        Mfa::sendCode($this->factorOf($user, ['type' => 'sms', 'destination' => self::PHONE])->id);

        self::assertMatchesRegularExpression('/^Your verification code is: \d{6}$/D', (string) $this->texts->lastTextTo(self::PHONE));

        $message = $this->lastMessage();

        self::assertStringContainsString('Your verification code is: <strong>' . $message->code . '</strong>', $message->render());
    }

    /**
     * Every placeholder in a line gets the code.
     *
     * @return void
     */
    public function testEveryPlaceholderGetsTheCode(): void
    {
        app('translator')->addLines(['messages.sms_code' => ':code est votre code. Encore : :code'], 'fr', 'mfa');
        app()->setLocale('fr');

        Mfa::sendCode($this->factorOf($this->signedInPerson(), ['type' => 'sms', 'destination' => self::PHONE])->id);

        self::assertMatchesRegularExpression('/^(\d{6}) est votre code\. Encore : \1$/D', (string) $this->texts->lastTextTo(self::PHONE));
    }

    /**
     * The code never reaches the translator, in its arguments or replacements,
     * on either channel.
     *
     * @return void
     */
    public function testTheCodeNeverReachesTheTranslator(): void
    {
        $translator = new RecordingTranslator($this->container()->make('translator'));

        $this->container()->instance('translator', $translator);
        $this->container()->instance(Translator::class, $translator);

        $user = $this->signedInPerson();

        Mfa::sendCode($this->emailFactor($user)->id);
        Mfa::sendCode($this->factorOf($user, ['type' => 'sms', 'destination' => self::PHONE])->id);

        $message = $this->lastMessage();
        $body    = (string) $message->content()->htmlString;

        self::assertStringContainsString($message->code, $body);
        self::assertNotSame([], $translator->given);

        preg_match('/\d{6}$/', (string) $this->texts->lastTextTo(self::PHONE), $sms);

        self::assertArrayHasKey(0, $sms);

        foreach ([$message->code, $sms[0]] as $code) {
            self::assertStringNotContainsString($code, (string) json_encode($translator->given));
        }
    }

    /**
     * A translator cannot inject markup: the whole line is escaped, the code's
     * own characters too, and only the package's tag surrounds the code.
     *
     * @return void
     */
    public function testALineAndTheCodeAreEscaped(): void
    {
        app('translator')->addLines([
            'messages.email_code'   => '<b onclick="x">Code</b> & :code \'here\'',
            'messages.email_expiry' => '<i>:minutes</i>',
            'messages.email_ignore' => '<script>alert(1)</script>',
        ], 'fr', 'mfa');

        $html = (new MfaCodeMessage('<a&"\'>', 5))->locale('fr')->render();

        self::assertStringContainsString('&lt;b onclick=&quot;x&quot;&gt;Code&lt;/b&gt; &amp; <strong>&lt;a&amp;&quot;&apos;&gt;</strong> &apos;here&apos;', $html);
        self::assertStringContainsString('&lt;i&gt;5&lt;/i&gt;', $html);
        self::assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $html);
        self::assertStringNotContainsString('<script>', $html);
        self::assertStringNotContainsString('<b ', $html);
    }

    /**
     * Invalid UTF-8 in a code or a line does not empty the body.
     *
     * @return void
     */
    public function testInvalidUtf8DoesNotEmptyTheBody(): void
    {
        $html = (new MfaCodeMessage("abc\xFF", 5))->render();

        self::assertStringContainsString('Your verification code is: <strong>abc', $html);
    }

    /**
     * The expiry is a real plural.
     *
     * @return void
     */
    public function testTheExpiryIsARealPlural(): void
    {
        self::assertStringContainsString('This code expires in 1 minute.', (new MfaCodeMessage('123456', 1))->render());
        self::assertStringContainsString('This code expires in 5 minutes.', (new MfaCodeMessage('123456', 5))->render());
    }

    /**
     * A subclass that chose a locale keeps it over the current one.
     *
     * @return void
     */
    public function testAnExplicitMessageLocaleWins(): void
    {
        config()->set('mfa.codes.mailable', ExplicitLocaleCodeMessage::class);

        app('translator')->addLines(['messages.email_code' => 'Ihr Code: :code'], 'de', 'mfa');
        app()->setLocale('fr');

        Mfa::sendCode($this->emailFactor($this->signedInPerson())->id);

        $message = $this->lastMessage();

        self::assertSame('de', $message->locale);
        self::assertStringContainsString('Ihr Code: <strong>', $message->render());
    }

    /**
     * The application's default locale is captured too, so a queue worker in
     * another locale renders the message as it was sent.
     *
     * @return void
     */
    public function testTheDefaultLocaleIsCaptured(): void
    {
        Mfa::sendCode($this->emailFactor($this->signedInPerson())->id);

        self::assertSame('en', $this->lastMessage()->locale);
    }

    /**
     * With no translator there is no locale to capture, and the message still
     * goes out, in the shipped English.
     *
     * @return void
     */
    public function testAMessageGoesOutWithoutALocaleWhenNoneIsKnown(): void
    {
        $container = Container::getInstance();

        Container::setInstance(new Container);

        try {
            (new MailEmailSender($this->outbox, new Repository))->send(CodeMessages::to(self::ADDRESS));

            $message = $this->lastMessage();

            self::assertNull($message->locale);
            self::assertSame('Your verification code', $message->envelope()->subject);
        } finally {
            Container::setInstance($container);
        }
    }

    /**
     * The payload a queue stores holds the message encrypted, it comes back on
     * the worker in the locale it was sent in, and the worker's own locale is
     * put back after it renders.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnEncryptedQueuedMessageRendersInItsLocaleOnTheWorker(): void
    {
        app()->setLocale('fr');

        Mfa::sendCode($this->emailFactor($this->signedInPerson())->id);

        $message = $this->lastMessage();

        app()->setLocale('de');

        $queue = new PayloadRecordingQueue;

        $queue->setContainer($this->container());

        $payload = $queue->payloadFor(new SendQueuedMailable($message));

        self::assertStringNotContainsString($message->code, $payload);

        $decoded = json_decode($payload, true);

        self::assertIsArray($decoded);

        $data = $decoded['data'] ?? null;

        self::assertIsArray($data);

        $command = $data['command'] ?? null;

        self::assertIsString($command);

        $serialized = $this->container()->make(Encrypter::class)->decrypt($command);

        self::assertIsString($serialized);

        $job = unserialize($serialized);

        self::assertInstanceOf(SendQueuedMailable::class, $job);
        self::assertInstanceOf(MfaCodeMessage::class, $job->mailable);
        self::assertSame('fr', $job->mailable->locale);
        self::assertStringContainsString('Votre code est : <strong>' . $message->code . '</strong>', $job->mailable->render());
        self::assertSame('de', app()->getLocale());
    }

    /**
     * Define the route the tests call: a send, behind a middleware choosing the
     * locale as an application's own would.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->post('code/{factor}', static fn (string $factor): array => ['sent' => Mfa::sendCode($factor)->wasSent()])
            ->middleware(ChooseLocale::class . ':fr');
    }

    /**
     * The code message last sent to the address.
     *
     * @return \SineMacula\Laravel\Mfa\Codes\MfaCodeMessage
     */
    private function lastMessage(): MfaCodeMessage
    {
        $message = $this->outbox->sent(MfaCodeMessage::class, static fn (MfaCodeMessage $mail): bool => $mail->hasTo(self::ADDRESS))->last();

        self::assertInstanceOf(MfaCodeMessage::class, $message);

        return $message;
    }
}
