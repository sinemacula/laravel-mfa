<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Missing destination exception.
 *
 * Thrown by OTP-delivery drivers when the factor they are asked to issue a
 * challenge against has no destination configured — the code would have nowhere
 * to go.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class MissingDestinationException extends \RuntimeException {}
