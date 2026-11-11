<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\RawMessage;

/**
 * Refuses every message, quoting its recipients and rendered body in the
 * exceptions, as a relay that echoes what it rejected would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingTransport implements TransportInterface
{
    /**
     * @return string
     */
    #[\Override]
    public function __toString(): string
    {
        return 'failing://';
    }

    /**
     * @param  \Symfony\Component\Mime\RawMessage  $message
     * @param  ?\Symfony\Component\Mailer\Envelope  $envelope
     * @return ?\Symfony\Component\Mailer\SentMessage
     *
     * @throws \Symfony\Component\Mailer\Exception\TransportException
     */
    #[\Override]
    public function send(RawMessage $message, ?Envelope $envelope = null): ?SentMessage
    {
        $recipients = implode(', ', array_map(static fn (Address $address): string => $address->getAddress(), $envelope?->getRecipients() ?? []));
        $body       = $message instanceof Email ? (string) $message->getHtmlBody() : '';

        throw new TransportException(sprintf('The relay refused the message to %s.', $recipients), 0, new \RuntimeException('Rejected body: ' . $body));
    }
}
