<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Applications;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Enums\RequirementMode;
use SineMacula\Laravel\Mfa\Requirements\FreshnessBounds;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * One application's settings in `mfa.applications.{name}`, read on every call.
 * Factors are stored once per identity; an application chooses what it accepts.
 *
 * A missing key takes the safe default, so an unconfigured name enables
 * nothing, and a malformed value fails closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApplicationSettings
{
    /** @var string */
    public const string APPLICATIONS = 'mfa.applications';

    /** @var int Default step-up age for the package's own operations, in seconds. */
    public const int FRESHNESS_SECONDS = 900;

    /** @var \SineMacula\Laravel\Mfa\Applications\ApplicationBlock Read on every call. */
    private ApplicationBlock $block;

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $name
     */
    public function __construct(

        /** Read on every call. */
        private Repository $config,

        // Its key in `mfa.applications`.
        string $name,
    ) {
        $this->block = new ApplicationBlock($config, $name);
    }

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public static function names(Repository $config): array
    {
        $applications = $config->get(self::APPLICATIONS) ?? [];

        if (!is_array($applications)) {
            throw new \InvalidArgumentException(sprintf('%s must be an array of application blocks keyed by name.', self::APPLICATIONS));
        }

        $names = [];

        foreach (array_keys($applications) as $name) {

            if (!is_string($name) || trim($name) === '') {
                throw new \InvalidArgumentException(sprintf('%s must be keyed by application name.', self::APPLICATIONS));
            }

            $names[] = $name;
        }

        return $names;
    }

    /**
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function types(): array
    {
        return $this->block->names('types', $this->block->all()['types'] ?? []);
    }

    /**
     * @param  string  $type
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function enables(string $type): bool
    {
        return in_array($type, $this->types(), true);
    }

    /**
     * Defaults to `never`.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\RequirementMode
     *
     * @throws \InvalidArgumentException
     */
    public function requirement(): RequirementMode
    {
        $mode = $this->block->all()['requirement'] ?? RequirementMode::NEVER->value;
        $read = is_string($mode) ? RequirementMode::tryFrom($mode) : null;

        if ($read === null) {
            throw new \InvalidArgumentException(sprintf('%s must be one of never, enrolled, always.', $this->block->key('requirement')));
        }

        return $read;
    }

    /**
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function acceptsRecoveryCodes(): bool
    {
        return $this->block->isEnabled('recovery_codes');
    }

    /**
     * The level a session needs to be issued recovery codes; `aal2` by default.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\AssuranceLevel
     *
     * @throws \InvalidArgumentException
     */
    public function recoveryCodeLevel(): AssuranceLevel
    {
        $level = $this->block->nested('recovery_codes')['level'] ?? AssuranceLevel::AAL2->value;
        $read  = is_string($level) ? AssuranceLevel::tryFrom($level) : null;

        if ($read === null || $read === AssuranceLevel::UNCLASSIFIED) {
            throw new \InvalidArgumentException(sprintf('%s must be one of aal1, aal2, aal3.', $this->block->key('recovery_codes.level')));
        }

        return $read;
    }

    /**
     * Whether a pending session with no factor may enrol its first one.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function allowsBootstrap(): bool
    {
        return $this->block->isEnabled('bootstrap');
    }

    /**
     * Enabled types only, and at least one when bootstrap is on.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function bootstrapTypes(): array
    {
        $enabled = $this->allowsBootstrap();
        $types   = $this->block->names('bootstrap.types', $this->block->nested('bootstrap')['types'] ?? []);

        if (array_diff($types, $this->types()) !== []) {
            $message = '%s must list only types the application enables in %s.';

            throw new \InvalidArgumentException(sprintf($message, $this->block->key('bootstrap.types'), $this->block->key('types')));
        }

        if ($types === [] && $enabled) {
            throw new \InvalidArgumentException(sprintf('%s must list at least one type while bootstrap is enabled.', $this->block->key('bootstrap.types')));
        }

        return $types;
    }

    /**
     * Defaults to 5, or the total limit when lower.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function confirmedPerTypeLimit(): int
    {
        $total = $this->confirmedLimit();

        return $this->limit('confirmed_per_type', min(5, $total), $total);
    }

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function confirmedLimit(): int
    {
        return $this->limit('confirmed', 10, 50);
    }

    /**
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function pendingLimit(): int
    {
        return $this->limit('pending', 2, 10);
    }

    /**
     * Falls back to `mfa.totp.window`.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function totpWindow(): int
    {
        $window = $this->block->all()['totp_window'] ?? null;

        return $window === null
            ? (new TotpSettings($this->config))->window()
            : IntegerSetting::from($this->block->key('totp_window'), $window, 0, 3);
    }

    /**
     * Each operation's step-up requirement. An entry replaces the default
     * whole; names are read as keys, never as dotted paths.
     *
     * @return array<string, \SineMacula\Laravel\Mfa\Requirements\Requirement>
     *
     * @throws \InvalidArgumentException
     */
    public function freshness(): array
    {
        $configured = $this->block->all()['freshness'] ?? [];
        $malformed  = '%s must map operation names, such as mfa.add_factor, to seconds or requirements.';

        if (!is_array($configured)) {
            throw new \InvalidArgumentException(sprintf($malformed, $this->block->key('freshness')));
        }

        $default   = Requirement::none()->withAdditionalVerification(self::FRESHNESS_SECONDS);
        $freshness = array_fill_keys(array_column(Operation::cases(), 'value'), $default);

        foreach ($configured as $operation => $entry) {

            if (!is_string($operation) || !Operation::isName($operation)) {
                throw new \InvalidArgumentException(sprintf($malformed, $this->block->key('freshness')));
            }

            $freshness[$operation] = $this->operationRequirement($this->block->key('freshness') . '.' . $operation, $entry);
        }

        return $freshness;
    }

    /**
     * Null when neither the package nor the application names the operation.
     *
     * @param  string  $operation
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    public function freshnessFor(string $operation): ?Requirement
    {
        return $this->freshness()[$operation] ?? null;
    }

    /**
     * @return ?\SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactor
     *
     * @throws \InvalidArgumentException
     */
    public function firstFactor(): ?DeclaredFirstFactor
    {
        if (($this->block->all()['first_factor'] ?? null) === null) {
            return null;
        }

        $declared = $this->block->nested('first_factor');
        $method   = $declared['method'] ?? null;
        $channel  = is_string($declared['channel'] ?? null) ? ChannelKind::tryFrom($declared['channel']) : null;

        if (!is_string($method) || trim($method) === '' || $channel === null || $channel === ChannelKind::UNKNOWN) {
            $message = '%s must be null, or a method and the kind of channel it proves (any channel kind but unknown).';

            throw new \InvalidArgumentException(sprintf($message, $this->block->key('first_factor')));
        }

        return new DeclaredFirstFactor($method, $channel);
    }

    /**
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->requirement();
        $this->acceptsRecoveryCodes();
        $this->recoveryCodeLevel();
        $this->bootstrapTypes();
        $this->confirmedPerTypeLimit();
        $this->pendingLimit();
        $this->totpWindow();
        $this->freshness();
        $this->firstFactor();
    }

    /**
     * Seconds for an additional verification within that age, or a serialised
     * requirement with at least one part, each within a day.
     *
     * @param  string  $key
     * @param  mixed  $entry
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    private function operationRequirement(string $key, mixed $entry): Requirement
    {
        if (!is_array($entry)) {
            return Requirement::none()->withAdditionalVerification(IntegerSetting::from($key, $entry, 1, FreshnessBounds::MOST_SECONDS));
        }

        try {
            $requirement = Requirement::fromArray($entry);
        } catch (\InvalidArgumentException $exception) {
            throw new \InvalidArgumentException(sprintf('%s must be seconds or a serialised requirement: %s', $key, $exception->getMessage()), 0, $exception);
        }

        if ($requirement->isEmpty()) {
            throw new \InvalidArgumentException(sprintf('%s must ask for at least one part.', $key));
        }

        return FreshnessBounds::assertBounded($requirement, $key);
    }

    /**
     * @param  string  $name
     * @param  int  $default
     * @param  int  $most
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function limit(string $name, int $default, int $most): int
    {
        return IntegerSetting::from($this->block->key('limits.' . $name), $this->block->nested('limits')[$name] ?? $default, 1, $most);
    }
}
