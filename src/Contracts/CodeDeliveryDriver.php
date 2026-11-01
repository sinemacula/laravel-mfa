<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonImmutable;

/**
 * Code delivery driver contract.
 *
 * A factor driver whose type proves possession of a destination by a code sent
 * to it (SMS, email). The package draws, stores and checks the code itself, as
 * a challenge bound to the factor, the identity, the application, the session
 * and the purpose, none of which the factor alone carries; the driver only
 * delivers each code to the factor's destination. Its codes are therefore never
 * sent or checked through `issueChallenge()`, `verify()` or `confirm()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CodeDeliveryDriver extends FactorDriver
{
    /**
     * Deliver the code to the factor's destination. It stops working at the
     * time given. An exception is the delivery's failure, and the code is then
     * not kept.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return void
     */
    public function deliver(Factor $factor, #[\SensitiveParameter] string $code, CarbonImmutable $expiresAt): void;
}
