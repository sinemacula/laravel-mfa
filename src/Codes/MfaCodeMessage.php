<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Mfa\Secrets\ExceptionScrubber;
use SineMacula\Laravel\Mfa\Secrets\SensitiveValues;
use SineMacula\Laravel\Mfa\Support\ConsumerMessages;

/**
 * Default Mailable for MFA email-code delivery.
 *
 * Ships an inline HTML body so the package works out of the box with no
 * published views. Consumers who want a branded email or a text alternative
 * subclass this Mailable, name the subclass in `mfa.codes.mailable`, and
 * override `content()` or `renderHtml()` to point at their own view.
 *
 * The code and expiry are exposed as public readonly properties so custom views
 * can render them as `{{ $code }}` / `{{ $expiresInMinutes }}`. The words are
 * translated (see `Support\ConsumerMessages`), in the locale Laravel enters
 * before it builds the envelope and the content; the driver captures the
 * current one on a message that chose none, so a queue worker renders it as it
 * was sent. Every line is plain text: a translation cannot inject markup. The
 * message carries the code in clear, so it is never queued in clear: whenever
 * it is queued, by a sender that queues it or by a subclass that is queueable,
 * the queue payload is encrypted with the application key.
 *
 * A failure while the message is sent, whether by the sender at once or by a
 * queue worker running the queued message, where the code service cannot catch
 * it, is scrubbed of the code and the recipients' addresses before it leaves
 * `send()` (see `Secrets\ExceptionScrubber`): in the message and the trace of
 * every exception in its chain, whether or not PHP recorded the arguments. The
 * values come from the message itself, so nothing is carried from one job to
 * the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @inheritable
 */
class MfaCodeMessage extends Mailable implements ShouldBeEncrypted
{
    use Queueable, SerializesModels;

    /**
     * Constructor.
     *
     * @param  string  $code
     * @param  int  $expiresInMinutes
     */
    public function __construct(

        /** The generated one-time code. */
        #[\SensitiveParameter]
        public readonly string $code,

        /** Minutes until the code expires. */
        public readonly int $expiresInMinutes,
    ) {}

    /**
     * Send the message through the mailer, scrubbing a failure of the code and
     * the recipients' addresses before rethrowing it.
     *
     * @param  \Illuminate\Contracts\Mail\Factory|\Illuminate\Contracts\Mail\Mailer  $mailer
     * @return \Illuminate\Mail\SentMessage|null
     *
     * @throws \Throwable
     */
    #[\Override]
    public function send($mailer)
    {
        // Laravel's send() declares no exception, but its transport throws
        try {
            return parent::send($mailer);
        } catch (\Throwable $exception) { // @phpstan-ignore catch.neverThrown
            ExceptionScrubber::scrub($exception, ...SensitiveValues::ofCodeMessage($this));

            throw $exception;
        }
    }

    /**
     * Build the envelope.
     *
     * @return \Illuminate\Mail\Mailables\Envelope
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: ConsumerMessages::line(ConsumerMessages::EMAIL_SUBJECT),
        );
    }

    /**
     * Build the content. Uses the `htmlString` parameter on `Content` so
     * consumers do not need to publish a view for the shipped default to
     * render.
     *
     * @return \Illuminate\Mail\Mailables\Content
     */
    public function content(): Content
    {
        return new Content(
            htmlString: $this->renderHtml(),
        );
    }

    /**
     * Render the HTML body: every translated line escaped whole, then the code,
     * escaped too, in place of its placeholder, so only the package's tags are
     * markup. The code goes in after the translator has answered, so it never
     * reaches the translator.
     *
     * @return string
     */
    protected function renderHtml(): string
    {
        return sprintf(
            '<p>%s</p><p>%s</p><p>%s</p>',
            str_replace(
                ConsumerMessages::CODE_PLACEHOLDER,
                '<strong>' . self::escape($this->code) . '</strong>',
                self::escape(ConsumerMessages::codeLine(ConsumerMessages::EMAIL_CODE)),
            ),
            self::escape(ConsumerMessages::minutesLine(ConsumerMessages::EMAIL_EXPIRY, $this->expiresInMinutes)),
            self::escape(ConsumerMessages::line(ConsumerMessages::EMAIL_IGNORE)),
        );
    }

    /**
     * Escape plain text for the HTML body, replacing what is not valid UTF-8
     * rather than emptying the line.
     *
     * @param  string  $text
     * @return string
     */
    private static function escape(#[\SensitiveParameter] string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
