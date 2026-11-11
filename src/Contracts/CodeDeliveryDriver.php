<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;

/**
 * A factor driver that only delivers codes; the bound `ChallengeGateway` draws
 * and checks them, never `verify()` or `confirm()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CodeDeliveryDriver extends FactorDriver
{
    /**
     * The destination in the one form the factor keeps and independence is
     * compared in, or `null` when it is not of this type.
     *
     * @param  string  $destination
     * @return ?string
     */
    public function normalizeDestination(#[\SensitiveParameter] string $destination): ?string;

    /**
     * Deliver to the message's destination; an exception fails the delivery and
     * drops the code.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     *
     * @throws \Throwable
     */
    public function deliver(Factor $factor, #[\SensitiveParameter] CodeMessage $message): void;
}
