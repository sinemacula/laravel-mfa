<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Concerns;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Secrets\QueryExceptionMask;

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
 * @copyright   2026 Sine Macula Limited
 */
trait ActsAsFactor // phpcs:ignore SineMacula.Metrics.MaxMethodCount.TooManyMethods
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
     * Return the factor's type: the name its driver is registered under.
     *
     * @return string
     */
    public function getType(): string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getTypeName());

        return is_string($value) ? $value : '';
    }

    /**
     * Column name holding the factor's type.
     *
     * @return string
     */
    public function getTypeName(): string
    {
        return 'type';
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
     * Return the factor's destination (phone number or email address).
     *
     * @return ?string
     */
    public function getDestination(): ?string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getDestinationName());

        return is_string($value) ? $value : null;
    }

    /**
     * Column name holding the delivery destination.
     *
     * @return string
     */
    public function getDestinationName(): string
    {
        return 'destination';
    }

    /**
     * Return the reference of the credential a passkey factor is associated
     * with.
     *
     * @return ?string
     */
    public function getCredentialReference(): ?string
    {
        return $this->readFactorString($this->getCredentialReferenceName());
    }

    /**
     * Column name holding a passkey factor's credential reference.
     *
     * @return string
     */
    public function getCredentialReferenceName(): string
    {
        return 'credential_reference';
    }

    /**
     * Return a TOTP factor's HMAC algorithm.
     *
     * @return ?string
     */
    public function getTotpAlgorithm(): ?string
    {
        return $this->readFactorString($this->getTotpAlgorithmName());
    }

    /**
     * Column name holding a TOTP factor's HMAC algorithm.
     *
     * @return string
     */
    public function getTotpAlgorithmName(): string
    {
        return 'totp_algorithm';
    }

    /**
     * Return the number of digits of a TOTP factor's codes.
     *
     * @return ?int
     */
    public function getTotpDigits(): ?int
    {
        return $this->readFactorInteger($this->getTotpDigitsName());
    }

    /**
     * Column name holding a TOTP factor's number of digits.
     *
     * @return string
     */
    public function getTotpDigitsName(): string
    {
        return 'totp_digits';
    }

    /**
     * Return the period of a TOTP factor's time steps in seconds.
     *
     * @return ?int
     */
    public function getTotpPeriod(): ?int
    {
        return $this->readFactorInteger($this->getTotpPeriodName());
    }

    /**
     * Column name holding a TOTP factor's period in seconds.
     *
     * @return string
     */
    public function getTotpPeriodName(): string
    {
        return 'totp_period';
    }

    /**
     * Return the last TOTP time step a code was accepted for.
     *
     * @return ?int
     */
    public function getLastAcceptedStep(): ?int
    {
        return $this->readFactorInteger($this->getLastAcceptedStepName());
    }

    /**
     * Column name holding the last accepted TOTP time step.
     *
     * @return string
     */
    public function getLastAcceptedStepName(): string
    {
        return 'last_accepted_step';
    }

    /**
     * Record the TOTP time step a code was accepted for if it is later than the
     * stored one: one conditional `UPDATE` of the factor's row, which the
     * database applies to the row as committed, so a request whose copy of the
     * factor is stale still cannot record a step another already has. A factor
     * not yet stored compares with its own attribute, as no other request can
     * see it.
     *
     * The recorded step is kept as the attribute's original value, so a later
     * `persist()` does not write it again over a later step another request
     * recorded in the meantime.
     *
     * @param  int  $step
     * @return bool
     */
    public function storeAcceptedStep(int $step): bool
    {
        $column = $this->getLastAcceptedStepName();

        if ($this->exists) {
            $recorded = $this->newModelQuery()
                ->whereKey($this->getKey())
                ->toBase()
                ->where(static function (Builder $query) use ($column, $step): void {
                    $query->whereNull($column)->orWhere($column, '<', $step);
                })
                ->update([$column => $step]) === 1;
        } else {
            $last     = $this->getLastAcceptedStep();
            $recorded = $last === null || $last < $step;
        }

        if ($recorded) {
            $this->setAttribute($column, $step);
            $this->syncOriginalAttribute($column);
        }

        return $recorded;
    }

    /**
     * Return where the factor is in its enrolment: pending unless the stored
     * status says confirmed, so a missing or unknown value is never usable.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\FactorStatus
     */
    public function getStatus(): FactorStatus
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getStatusName());

        if ($value instanceof FactorStatus) {
            return $value;
        }

        return $value === FactorStatus::CONFIRMED->value ? FactorStatus::CONFIRMED : FactorStatus::PENDING;
    }

    /**
     * Column name holding the factor's status.
     *
     * @return string
     */
    public function getStatusName(): string
    {
        return 'status';
    }

    /**
     * Determine whether the factor is confirmed, and so usable.
     *
     * @return bool
     */
    public function isConfirmed(): bool
    {
        return $this->getStatus() === FactorStatus::CONFIRMED;
    }

    /**
     * Determine whether the factor is the identity's preferred one.
     *
     * @return bool
     */
    public function isPreferred(): bool
    {
        return $this->getAttribute($this->getPreferredName()) === true;
    }

    /**
     * Column name holding whether the factor is the preferred one.
     *
     * @return string
     */
    public function getPreferredName(): string
    {
        return 'preferred';
    }

    /**
     * Return the factor's count of consecutive failed verifications.
     *
     * @return int
     */
    public function getConsecutiveFailures(): int
    {
        return $this->readFactorInteger($this->getConsecutiveFailuresName()) ?? 0;
    }

    /**
     * Column name holding the count of consecutive failed verifications.
     *
     * @return string
     */
    public function getConsecutiveFailuresName(): string
    {
        return 'consecutive_failures';
    }

    /**
     * Return when the factor was disabled at the failure ceiling.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getDisabledAt(): ?CarbonInterface
    {
        return $this->readFactorTime($this->getDisabledAtName());
    }

    /**
     * Column name holding when the factor was disabled at the failure ceiling.
     *
     * @return string
     */
    public function getDisabledAtName(): string
    {
        return 'disabled_at';
    }

    /**
     * Return the application the factor was enrolled through.
     *
     * @return ?string
     */
    public function getApplication(): ?string
    {
        return $this->readFactorString($this->getApplicationName());
    }

    /**
     * Column name holding the application the factor was enrolled through.
     *
     * @return string
     */
    public function getApplicationName(): string
    {
        return 'application';
    }

    /**
     * Return when the factor was confirmed.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getConfirmedAt(): ?CarbonInterface
    {
        return $this->readFactorTime($this->getConfirmedAtName());
    }

    /**
     * Column name holding when the factor was confirmed.
     *
     * @return string
     */
    public function getConfirmedAtName(): string
    {
        return 'confirmed_at';
    }

    /**
     * Return when the factor was last used to verify.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastUsedAt(): ?CarbonInterface
    {
        return $this->readFactorTime($this->getLastUsedAtName());
    }

    /**
     * Column name holding when the factor was last used.
     *
     * @return string
     */
    public function getLastUsedAtName(): string
    {
        return 'last_used_at';
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
     * Stamp a successful verification as the factor's last use.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function recordVerification(?CarbonInterface $at = null): void
    {
        $this->setAttribute($this->getLastUsedAtName(), $at ?? Carbon::now());
    }

    /**
     * Mark the factor confirmed at the given time or now.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function confirm(?CarbonInterface $at = null): void
    {
        $this->setAttribute($this->getStatusName(), FactorStatus::CONFIRMED->value);
        $this->setAttribute($this->getConfirmedAtName(), $at ?? Carbon::now());
    }

    /**
     * Persist pending mutations to the underlying storage, throwing when a
     * model event cancels the save, so the change it is part of never reports a
     * state that was not stored. A failed query leaves with nothing it was
     * given, since a factor binds a destination and a credential reference as
     * they are (see `Secrets\QueryExceptionMask`).
     *
     * @return void
     *
     * @throws \Illuminate\Database\QueryException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    public function persist(): void
    {
        try {
            $saved = $this->save();
        } catch (QueryException $failure) { // @phpstan-ignore catch.neverThrown
            QueryExceptionMask::mask($failure);

            throw $failure;
        }

        if (!$saved) {
            throw new WriteCanceledException('A model event cancelled the factor\'s save, so the change it is part of was not made.');
        }
    }

    /**
     * Read a string column, `null` for anything else.
     *
     * @param  string  $column
     * @return ?string
     */
    private function readFactorString(string $column): ?string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($column);

        return is_string($value) ? $value : null;
    }

    /**
     * Read an integer column, `null` for anything else.
     *
     * @param  string  $column
     * @return ?int
     */
    private function readFactorInteger(string $column): ?int
    {
        /** @var mixed $value */
        $value = $this->getAttribute($column);

        return is_int($value) ? $value : null;
    }

    /**
     * Read a time column, `null` for anything else.
     *
     * @param  string  $column
     * @return ?\Carbon\CarbonInterface
     */
    private function readFactorTime(string $column): ?CarbonInterface
    {
        /** @var mixed $value */
        $value = $this->getAttribute($column);

        return $value instanceof CarbonInterface ? $value : null;
    }
}
