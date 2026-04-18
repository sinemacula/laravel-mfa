<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Traits;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Default implementation of the `Factor` contract for Eloquent models.
 *
 * Consumers who want to swap the shipped `Factor` model for their own can apply
 * this trait to their custom model and satisfy the contract with zero
 * additional code. Column names are exposed via override hooks (`get*Name()`
 * methods) so implementations can remap columns without overriding the
 * accessors themselves.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
trait ActsAsFactor
{
    /**
     * Polymorphic relation to the owning authenticatable identity.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function authenticatable(): MorphTo
    {
        // morphTo() returns `MorphTo<Model, $this>` but the EloquentFactor
        // contract requires `MorphTo<Model, Model>` — the bound is widened, not
        // narrowed.
        // @phpstan-ignore return.type
        return $this->morphTo();
    }

    /**
     * Return the factor's stable identifier.
     *
     * @return mixed
     */
    public function getFactorIdentifier(): mixed
    {
        return $this->getKey();
    }

    /**
     * Return the driver name this factor is registered against.
     *
     * @return string
     */
    public function getDriver(): string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getDriverName());

        return is_string($value) ? $value : '';
    }

    /**
     * Column name holding the driver identifier.
     *
     * @return string
     */
    public function getDriverName(): string
    {
        return 'driver';
    }

    /**
     * Return the factor's human-readable label.
     *
     * @return ?string
     */
    public function getLabel(): ?string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getLabelName());

        return is_string($value) ? $value : null;
    }

    /**
     * Column name holding the human-readable label.
     *
     * @return string
     */
    public function getLabelName(): string
    {
        return 'label';
    }

    /**
     * Return the factor's delivery destination (phone number / email).
     *
     * @return ?string
     */
    public function getRecipient(): ?string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getRecipientName());

        return is_string($value) ? $value : null;
    }

    /**
     * Column name holding the delivery destination.
     *
     * @return string
     */
    public function getRecipientName(): string
    {
        return 'recipient';
    }

    /**
     * Return the authenticatable the factor belongs to. Returns `null` when the
     * `authenticatable` relation has not been loaded — this accessor MUST NOT
     * trigger a lazy query. Callers that need the related record should
     * eager-load the relation on the query first.
     *
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    public function getAuthenticatable(): ?Authenticatable
    {
        if (!$this->relationLoaded('authenticatable')) {
            return null;
        }

        /** @var mixed $related */
        $related = $this->getRelation('authenticatable');

        return $related instanceof Authenticatable ? $related : null;
    }

    /**
     * Return the persistent secret, if any.
     *
     * @return ?string
     */
    public function getSecret(): ?string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getSecretName());

        return is_string($value) ? $value : null;
    }

    /**
     * Column name holding the persistent secret.
     *
     * @return string
     */
    public function getSecretName(): string
    {
        return 'secret';
    }

    /**
     * Return the currently issued one-time code, if any.
     *
     * @return ?string
     */
    public function getCode(): ?string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getCodeName());

        return is_string($value) ? $value : null;
    }

    /**
     * Column name holding the pending one-time code.
     *
     * @return string
     */
    public function getCodeName(): string
    {
        return 'code';
    }

    /**
     * Return when the currently issued one-time code expires.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getExpiresAt(): ?CarbonInterface
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getExpiresAtName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * Column name holding the expiry of the pending one-time code.
     *
     * @return string
     */
    public function getExpiresAtName(): string
    {
        return 'expires_at';
    }

    /**
     * Determine whether the factor is currently locked.
     *
     * @return bool
     */
    public function isLocked(): bool
    {
        $until = $this->getLockedUntil();

        return $until !== null && $until->isFuture();
    }

    /**
     * Return when the factor is locked until, or `null`.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLockedUntil(): ?CarbonInterface
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getLockedUntilName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * Column name holding the lockout expiry timestamp.
     *
     * @return string
     */
    public function getLockedUntilName(): string
    {
        return 'locked_until';
    }

    /**
     * Return when verification was last attempted.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastAttemptedAt(): ?CarbonInterface
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getLastAttemptedAtName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * Column name holding the last-attempted timestamp.
     *
     * @return string
     */
    public function getLastAttemptedAtName(): string
    {
        return 'last_attempted_at';
    }

    /**
     * Determine whether the factor has ever completed a successful
     * verification.
     *
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->getVerifiedAt() !== null;
    }

    /**
     * Return when the factor was last successfully verified.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getVerifiedAt(): ?CarbonInterface
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getVerifiedAtName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * Column name holding the last-verified timestamp.
     *
     * @return string
     */
    public function getVerifiedAtName(): string
    {
        return 'verified_at';
    }

    /**
     * Increment the attempt counter and stamp the last-attempted timestamp.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function recordAttempt(?CarbonInterface $at = null): void
    {
        $this->setAttribute(
            $this->getAttemptsName(),
            $this->getAttempts() + 1,
        );
        $this->setAttribute(
            $this->getLastAttemptedAtName(),
            $at ?? Carbon::now(),
        );
    }

    /**
     * Column name holding the failed-attempt counter.
     *
     * @return string
     */
    public function getAttemptsName(): string
    {
        return 'attempts';
    }

    /**
     * Return the number of consecutive failed attempts.
     *
     * @return int
     */
    public function getAttempts(): int
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getAttemptsName());

        return is_int($value) ? $value : 0;
    }

    /**
     * Apply a lockout window deferring further verification attempts.
     *
     * @param  \Carbon\CarbonInterface  $until
     * @return void
     */
    public function applyLockout(CarbonInterface $until): void
    {
        $this->setAttribute($this->getLockedUntilName(), $until);
    }

    /**
     * Stamp a successful verification and reset the attempt state.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function recordVerification(?CarbonInterface $at = null): void
    {
        $this->setAttribute(
            $this->getVerifiedAtName(),
            $at ?? Carbon::now(),
        );
        $this->resetAttempts();
        $this->consumeCode();
    }

    /**
     * Reset the attempt counter and clear any active lockout.
     *
     * @return void
     */
    public function resetAttempts(): void
    {
        $this->setAttribute($this->getAttemptsName(), 0);
        $this->setAttribute($this->getLockedUntilName(), null);
    }

    /**
     * Clear any pending one-time code and its expiry.
     *
     * @return void
     */
    public function consumeCode(): void
    {
        $this->setAttribute($this->getCodeName(), null);
        $this->setAttribute($this->getExpiresAtName(), null);
    }

    /**
     * Persist a newly issued one-time code and its expiry.
     *
     * @param  string  $code
     * @param  \Carbon\CarbonInterface  $expiresAt
     * @return void
     */
    public function issueCode(#[\SensitiveParameter] string $code, CarbonInterface $expiresAt): void
    {
        $this->setAttribute($this->getCodeName(), $code);
        $this->setAttribute($this->getExpiresAtName(), $expiresAt);
    }

    /**
     * Persist pending mutations to the underlying storage.
     *
     * @return void
     */
    public function persist(): void
    {
        $this->save();
    }
}
