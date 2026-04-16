<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * SMS gateway not configured exception.
 *
 * Thrown by the `NullSmsGateway` default when the SMS factor driver
 * tries to issue a challenge without a real gateway bound. Surfaces
 * the missing binding to the developer rather than silently dropping
 * the outbound message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class SmsGatewayNotConfiguredException extends \RuntimeException {}
