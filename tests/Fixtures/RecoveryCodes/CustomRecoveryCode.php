<?php

declare(strict_types = 1);

namespace Tests\Fixtures\RecoveryCodes;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Mfa\Concerns\ActsAsRecoveryCode;
use SineMacula\Laravel\Mfa\Contracts\RecoveryCode;

/**
 * An application's own recovery code model on its own table, with every column
 * named differently from the shipped model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CustomRecoveryCode extends Model implements RecoveryCode
{
    use ActsAsRecoveryCode;

    /** @var ?string */
    protected $table = 'test_recovery_codes';

    /**
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    #[\Override]
    public function authenticatable(): MorphTo
    {
        // @phpstan-ignore return.type
        return $this->morphTo('owner', 'owner_type', 'owner_id');
    }

    /**
     * @return string
     */
    #[\Override]
    public function getOwnerHashName(): string
    {
        return 'owner_digest';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getCodeHashName(): string
    {
        return 'hash';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getGenerationName(): string
    {
        return 'set_number';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getUsedAtName(): string
    {
        return 'redeemed_at';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getReplacedAtName(): string
    {
        return 'retired_at';
    }

    /**
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'set_number'  => 'integer',
            'redeemed_at' => 'datetime',
            'retired_at'  => 'datetime',
        ];
    }
}
