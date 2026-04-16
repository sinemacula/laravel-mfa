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
 * Ships an inline HTML body so the package works out of the box with
 * no published views. Consumers who want a branded email / a text
 * alternative subclass this Mailable (or configure the email driver
 * to use their own Mailable class) and override `content()` or
 * `renderHtml()` to point at their own view.
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
     * Build the content. Uses the `htmlString` parameter on `Content`
     * so consumers do not need to publish a view for the shipped
     * default to render.
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
