<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;

/**
 * Code delivery driver contract.
 *
 * A factor driver whose type proves possession of a destination by a code sent
 * to it (SMS, email). The bound `ChallengeGateway` draws, stores and checks the
 * code, as a challenge bound to the factor, the identity, the application, the
 * session and the purpose, none of which the factor alone carries; the driver
 * only delivers each code to the factor's destination. Its codes are therefore
 * never checked through `verify()` or `confirm()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CodeDeliveryDriver extends FactorDriver
{
    /**
     * The destination in the one form the factor keeps, and independence is
     * compared in, or `null` when it is not a destination of this type. It is
     * captured when the enrolment starts, and never resolved from the identity
     * afterwards.
     *
     * @param  string  $destination
     * @return ?string
     */
    public function normalizeDestination(#[\SensitiveParameter] string $destination): ?string;

    /**
     * Deliver the message's code to its destination. The factor is the one the
     * message describes, as locked when the code was drawn; the destination to
     * send to is the message's. An exception is the delivery's failure, and the
     * code is then not kept.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     *
     * @throws \Throwable
     */
    public function deliver(Factor $factor, #[\SensitiveParameter] CodeMessage $message): void;
}
