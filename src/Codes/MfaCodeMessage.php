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
 * Default code email with an inline body, so no views need publishing.
 * Encrypted when queued because it carries the code in clear.
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
     * @param  string  $code
     * @param  int  $expiresInMinutes
     */
    public function __construct(

        /** Code in clear. */
        #[\SensitiveParameter]
        public readonly string $code,

        /** Minutes until the code expires. */
        public readonly int $expiresInMinutes,
    ) {}

    /**
     * Scrub the code and recipients from a failure, which on a queue worker the
     * code service never sees.
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
     * @return \Illuminate\Mail\Mailables\Envelope
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: ConsumerMessages::line(ConsumerMessages::EMAIL_SUBJECT),
        );
    }

    /**
     * @return \Illuminate\Mail\Mailables\Content
     */
    public function content(): Content
    {
        return new Content(
            htmlString: $this->renderHtml(),
        );
    }

    /**
     * Lines are escaped before the code is inserted, so a translation cannot
     * inject markup and the code never reaches the translator.
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
     * Substitute invalid UTF-8 rather than emptying the line.
     *
     * @param  string  $text
     * @return string
     */
    private static function escape(#[\SensitiveParameter] string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
