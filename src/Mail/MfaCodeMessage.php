<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

/**
 * Default Mailable for MFA email-code delivery.
 *
 * Ships an inline plain-text body so the package works out of the box
 * with no published views. Consumers who want a branded email / HTML
 * layout subclass this Mailable (or configure the email driver to use
 * their own Mailable class) and override `content()` to point at their
 * own view.
 *
 * The code and expiry are exposed as public readonly properties so
 * custom views can render them as `{{ $code }}` / `{{ $expiresInMinutes }}`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class MfaCodeMessage extends Mailable
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

        /** Minutes until the code expires from the factor's point of view. */
        public readonly int $expiresInMinutes,

    ) {}

    /**
     * Build the envelope.
     *
     * @return \Illuminate\Mail\Mailables\Envelope
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: 'Your verification code',
        );
    }

    /**
     * Build the content.
     *
     * @return \Illuminate\Mail\Mailables\Content
     */
    public function content(): Content
    {
        // Raw-string bodies go through positional args — view / html / text
        // / markdown / with / htmlString / textString — because larastan's
        // Content stub is currently missing the two trailing parameters.
        // @phpstan-ignore arguments.count
        return new Content(
            null,
            null,
            null,
            null,
            [],
            $this->renderHtml(),
            $this->renderText(),
        );
    }

    /**
     * Render the plain-text body.
     *
     * @return string
     */
    protected function renderText(): string
    {
        return sprintf(
            "Your verification code is: %s\n\n"
            . "This code expires in %d minute(s).\n\n"
            . 'If you did not request this code, you can safely ignore this message.',
            $this->code,
            $this->expiresInMinutes,
        );
    }

    /**
     * Render the HTML body.
     *
     * @return string
     */
    protected function renderHtml(): string
    {
        return sprintf(
            '<p>Your verification code is: <strong>%s</strong></p>'
            . '<p>This code expires in %d minute(s).</p>'
            . '<p>If you did not request this code, you can safely ignore '
            . 'this message.</p>',
            htmlspecialchars($this->code, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            $this->expiresInMinutes,
        );
    }
}
