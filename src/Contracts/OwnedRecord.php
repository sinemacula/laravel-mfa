<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * A stored record kept by owner, found by the hash of its owner's type and key
 * rather than the owner columns a collation may compare without case.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface OwnedRecord
{
    /**
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function authenticatable(): MorphTo;

    /**
     * The column holding `ProofOwner::hash()` of the owner, which every save
     * must keep in step with the owner columns.
     *
     * @return string
     */
    public function getOwnerHashName(): string;
}
