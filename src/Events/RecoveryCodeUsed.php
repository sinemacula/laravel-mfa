<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when a recovery code is redeemed, with how many of the set remain
 * unused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecoveryCodeUsed extends RecoveryCodeRedemptionEvent {}
