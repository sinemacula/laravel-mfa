<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when a redemption leaves the recovery code set at or below its low
 * count, so the application can prompt for a new set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecoveryCodesLow extends RecoveryCodeRedemptionEvent {}
