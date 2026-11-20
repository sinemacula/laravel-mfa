<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Concerns;

use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * `OwnedRecord` for an Eloquent model: every save sets the owner hash from the
 * owner columns its `authenticatable` relation names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait HashesOwner
{
    /**
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function authenticatable(): MorphTo
    {
        // The contract widens morphTo()'s `MorphTo<Model, $this>` bound.
        // @phpstan-ignore return.type
        return $this->morphTo();
    }

    /**
     * @return string
     */
    public function getOwnerHashName(): string
    {
        return 'owner_hash';
    }

    /**
     * @return void
     */
    protected static function bootHashesOwner(): void
    {
        static::saving(static function (self $model): void {

            // Blank, as a stored model's relation would build its owner.
            $relation = $model->newInstance()->authenticatable();
            $type     = $model->getAttribute($relation->getMorphType());
            $key      = $model->getAttribute($relation->getForeignKeyName());

            if (!is_string($type) || (!is_string($key) && !is_int($key))) {
                return;
            }

            $model->setAttribute($model->getOwnerHashName(), (new ProofOwner($type, (string) $key))->hash());
        });
    }
}
