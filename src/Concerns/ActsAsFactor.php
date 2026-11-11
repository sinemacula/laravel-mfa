<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Concerns;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Secrets\QueryExceptionMask;

/**
 * `Factor` for an Eloquent model; override a `get*Name()` method to remap its
 * column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ActsAsFactor // phpcs:ignore SineMacula.Metrics.MaxMethodCount.TooManyMethods
{
    /**
     * Casts the lockout and disabled columns a refusal reads as datetimes,
     * unless the model declares its own cast for them.
     *
     * @return void
     */
    public function initializeActsAsFactor(): void
    {
        foreach ([$this->getLockedUntilName(), $this->getDisabledAtName()] as $column) {

            if ($this->hasCast($column)) {
                continue;
            }

            $this->mergeCasts([$column => 'datetime']);
        }
    }

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
     * @return mixed
     */
    public function getFactorIdentifier(): mixed
    {
        return $this->getKey();
    }

    /**
     * The name its driver is registered under.
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
     * @return string
     */
    public function getTypeName(): string
    {
        return 'type';
    }

    /**
     * @return ?string
     */
    public function getLabel(): ?string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getLabelName());

        return is_string($value) ? $value : null;
    }

    /**
     * @return string
     */
    public function getLabelName(): string
    {
        return 'label';
    }

    /**
     * A phone number or email address.
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
     * @return string
     */
    public function getDestinationName(): string
    {
        return 'destination';
    }

    /**
     * @return ?string
     */
    public function getCredentialReference(): ?string
    {
        return $this->readFactorString($this->getCredentialReferenceName());
    }

    /**
     * @return string
     */
    public function getCredentialReferenceName(): string
    {
        return 'credential_reference';
    }

    /**
     * @return ?string
     */
    public function getTotpAlgorithm(): ?string
    {
        return $this->readFactorString($this->getTotpAlgorithmName());
    }

    /**
     * @return string
     */
    public function getTotpAlgorithmName(): string
    {
        return 'totp_algorithm';
    }

    /**
     * @return ?int
     */
    public function getTotpDigits(): ?int
    {
        return $this->readFactorInteger($this->getTotpDigitsName());
    }

    /**
     * @return string
     */
    public function getTotpDigitsName(): string
    {
        return 'totp_digits';
    }

    /**
     * Time step length in seconds.
     *
     * @return ?int
     */
    public function getTotpPeriod(): ?int
    {
        return $this->readFactorInteger($this->getTotpPeriodName());
    }

    /**
     * @return string
     */
    public function getTotpPeriodName(): string
    {
        return 'totp_period';
    }

    /**
     * @return ?int
     */
    public function getLastAcceptedStep(): ?int
    {
        return $this->readFactorInteger($this->getLastAcceptedStepName());
    }

    /**
     * @return string
     */
    public function getLastAcceptedStepName(): string
    {
        return 'last_accepted_step';
    }

    /**
     * Records a later step with one conditional `UPDATE` on the committed row,
     * so a stale copy cannot replay a step. It is synced as the original value
     * so a later `persist()` cannot overwrite a newer step.
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
     * Pending only for an unsaved factor with no status; any unknown value
     * throws, as an unconfirmed read can skip a stronger proof. An enum cast
     * fails closed first with `ValueError`.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\FactorStatus
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function getStatus(): FactorStatus
    {
        $column = $this->getStatusName();

        /** @var mixed $value */
        $value  = $this->getAttribute($column);
        $status = is_string($value) ? FactorStatus::tryFrom($value) : $value;

        if ($status instanceof FactorStatus) {
            return $status;
        }

        if ($value === null && !$this->exists) {
            return FactorStatus::PENDING;
        }

        throw new InvalidModelException(sprintf('The factor\'s column [%s] holds no status the package knows, so whether it is confirmed cannot be told.', $column));
    }

    /**
     * @return string
     */
    public function getStatusName(): string
    {
        return 'status';
    }

    /**
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function isConfirmed(): bool
    {
        return $this->getStatus() === FactorStatus::CONFIRMED;
    }

    /**
     * @return bool
     */
    public function isPreferred(): bool
    {
        return $this->getAttribute($this->getPreferredName()) === true;
    }

    /**
     * @return string
     */
    public function getPreferredName(): string
    {
        return 'preferred';
    }

    /**
     * @return int
     */
    public function getConsecutiveFailures(): int
    {
        return $this->readFactorInteger($this->getConsecutiveFailuresName()) ?? 0;
    }

    /**
     * @return string
     */
    public function getConsecutiveFailuresName(): string
    {
        return 'consecutive_failures';
    }

    /**
     * Throws on a value that is not a time, as never disabled would enable the
     * factor.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function getDisabledAt(): ?CarbonInterface
    {
        return $this->readRefusalTime($this->getDisabledAtName(), 'disabled');
    }

    /**
     * @return string
     */
    public function getDisabledAtName(): string
    {
        return 'disabled_at';
    }

    /**
     * As held on this instance. Throws on a value that is not a time, as no
     * deadline would unlock the factor.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function getLockedUntil(): ?CarbonInterface
    {
        return $this->readRefusalTime($this->getLockedUntilName(), 'locked');
    }

    /**
     * @return string
     */
    public function getLockedUntilName(): string
    {
        return 'locked_until';
    }

    /**
     * The application the factor was enrolled through.
     *
     * @return ?string
     */
    public function getApplication(): ?string
    {
        return $this->readFactorString($this->getApplicationName());
    }

    /**
     * @return string
     */
    public function getApplicationName(): string
    {
        return 'application';
    }

    /**
     * @return ?\Carbon\CarbonInterface
     */
    public function getConfirmedAt(): ?CarbonInterface
    {
        return $this->readFactorTime($this->getConfirmedAtName());
    }

    /**
     * @return string
     */
    public function getConfirmedAtName(): string
    {
        return 'confirmed_at';
    }

    /**
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastUsedAt(): ?CarbonInterface
    {
        return $this->readFactorTime($this->getLastUsedAtName());
    }

    /**
     * @return string
     */
    public function getLastUsedAtName(): string
    {
        return 'last_used_at';
    }

    /**
     * @return ?string
     */
    public function getSecret(): ?string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getSecretName());

        return is_string($value) ? $value : null;
    }

    /**
     * @return string
     */
    public function getSecretName(): string
    {
        return 'secret';
    }

    /**
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function recordVerification(?CarbonInterface $at = null): void
    {
        $this->setAttribute($this->getLastUsedAtName(), $at ?? Carbon::now());
    }

    /**
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function confirm(?CarbonInterface $at = null): void
    {
        $this->setAttribute($this->getStatusName(), FactorStatus::CONFIRMED->value);
        $this->setAttribute($this->getConfirmedAtName(), $at ?? Carbon::now());
    }

    /**
     * Throws when a model event cancels the save. A failed query is masked, as
     * its bindings carry the destination and credential reference.
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
     * `null` only when nothing is stored. A blank throws, as a datetime cast
     * would read it as now; the message names the column, never the value.
     *
     * @param  string  $column
     * @param  string  $state
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function readRefusalTime(string $column, string $state): ?CarbonInterface
    {
        $stored = $this->getAttributes()[$column] ?? null;

        if ($stored === null) {
            return null;
        }

        $time = is_string($stored) && trim($stored) === '' ? null : $this->getAttribute($column);

        if ($time instanceof CarbonInterface) {
            return $time;
        }

        throw new InvalidModelException(sprintf('The factor\'s column [%s] does not read as a time, so whether it is %s cannot be told.', $column, $state));
    }

    /**
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
