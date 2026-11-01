<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Contracts\Mail\Mailer;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Exceptions\MissingDestinationException;

/**
 * Email factor driver.
 *
 * Issues one-time codes via Laravel's mail subsystem and verifies them in
 * constant time. The shipped `MfaCodeMessage` Mailable carries an inline HTML
 * body so the package works with no published views; consumers who want a
 * branded email subclass the Mailable (or pass their own Mailable class via the
 * driver constructor) and override its `content()` to point at their own view.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class EmailDriver extends AbstractOtpDriver
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Mail\Mailer  $mailer
     * @param  class-string<\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage>  $mailable
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  ?callable(int, int): int  $randomInt
     */
    public function __construct(

        /** Laravel mailer used to dispatch the outbound code. */
        private readonly Mailer $mailer,

        /** Mailable class responsible for rendering the code email. */
        private readonly string $mailable = MfaCodeMessage::class,

        // Generated code length; passthrough to `AbstractOtpDriver`.
        int $codeLength = 6,

        // Code lifetime in minutes; passthrough to `AbstractOtpDriver`.
        int $expiry = 10,

        // Randomness seam; passthrough to `AbstractOtpDriver`.
        ?callable $randomInt = null,
    ) {
        parent::__construct($codeLength, $expiry, $randomInt);
    }

    /**
     * A code sent by email to the factor's address.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::EMAIL;
    }

    /**
     * Get the configured Mailable class.
     *
     * @return class-string<\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage>
     */
    public function getMailable(): string
    {
        return $this->mailable;
    }

    /**
     * Dispatch the Mailable to the factor's destination email.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $code
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\MissingDestinationException
     */
    #[\Override]
    protected function dispatch(EloquentFactor $factor, #[\SensitiveParameter] string $code): void
    {
        $destination = $factor->getDestination();

        if ($destination === null || $destination === '') {
            throw new MissingDestinationException('Email factor has no destination configured; cannot deliver code.');
        }

        /** @var \SineMacula\Laravel\Mfa\Codes\MfaCodeMessage $message */
        $message = new ($this->mailable)($code, $this->getExpiry());

        $this->mailer->to($destination)->send($message);
    }
}
