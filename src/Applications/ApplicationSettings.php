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
 * One application's settings in `mfa.applications.{name}`: what it accepts and
 * offers of the factors, recovery codes and attempt state an identity holds in
 * every application. Factors are stored once per identity; an application only
 * chooses the factor types it enables, when it requires one, whether it accepts
 * recovery codes, whether a pending session may enrol its first factor, its
 * limits on enrolments made through it, its TOTP window, the requirement each
 * operation's step-up must meet, and the first factor its guard uses.
 *
 * Every setting is read from the configuration on every call, so a change
 * applies at once and nothing is cached between requests. A key missing from
 * the block takes the production-safe default: no type enabled, no factor
 * required, no recovery codes and no bootstrap. An application with no block at
 * all takes every default, so a name nobody configured enables nothing. A
 * malformed value, or a key the block does not know, fails closed with an
 * `InvalidArgumentException` naming the key; the package checks every
 * configured application when it boots and `mfa:check` reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApplicationSettings
{
    /** @var string The key holding every application's block. */
    public const string APPLICATIONS = 'mfa.applications';

    /** @var int The maximum age, in seconds, of the additional verification each of the package's own operations asks for when the application sets nothing. */
    public const int FRESHNESS_SECONDS = 900;

    /** @var \SineMacula\Laravel\Mfa\Applications\ApplicationBlock The application's block, read on every call. */
    private ApplicationBlock $block;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $name
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,

        /** The application's name: its key in `mfa.applications`. */
        public string $name,
    ) {
        $this->block = new ApplicationBlock($config, $name);
    }

    /**
     * The names of the configured applications, in the order they are
     * configured.
     *
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
     * The factor types the application enables, none unless listed.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function types(): array
    {
        return $this->block->names('types', $this->block->all()['types'] ?? []);
    }

    /**
     * Whether the application enables the factor type.
     *
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
     * When the application requires an additional factor: `never` (the
     * default), `enrolled` or `always`.
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
     * Whether the application accepts recovery codes, off by default.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function acceptsRecoveryCodes(): bool
    {
        return $this->block->isEnabled('recovery_codes');
    }

    /**
     * The assurance level a session needs before it may be issued recovery
     * codes: `aal2` by default, or `aal1` or `aal3`.
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
     * Whether a pending session with no factor may enrol its first one, off by
     * default.
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
     * The factor types a pending session may enrol as its first one: types the
     * application enables, at least one when bootstrap is on.
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
     * How many confirmed factors of one type an identity may enrol through the
     * application, from 1 to the total limit; 5 by default, or the total limit
     * when that is lower.
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
     * How many confirmed factors an identity may enrol through the application
     * in total, 1 to 50; 10 by default.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function confirmedLimit(): int
    {
        return $this->limit('confirmed', 10, 50);
    }

    /**
     * How many enrolments an identity may have pending through the application
     * at once, 1 to 10; 2 by default.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function pendingLimit(): int
    {
        return $this->limit('pending', 2, 10);
    }

    /**
     * How many TOTP time steps either side of the current one the application
     * accepts, 0 to 3; `mfa.totp.window` when it sets none.
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
     * The requirement each operation's step-up must meet: the package's own
     * operations ask for an additional verification within
     * `FRESHNESS_SECONDS` unless the application sets them, and any operation
     * of the application's own it names has the requirement it sets. An entry
     * is either a number of seconds, 1 to 86400, for an additional
     * verification within that age, or a serialised requirement (see
     * `Requirement::fromArray()`) asking for at least one part, each with a
     * `max_age` of 1 to 86400 seconds. An entry replaces the package's default
     * for its operation whole. Names are the block's keys, read whole, never as
     * a dotted path, and must be in the form an operation's name takes (see
     * `Operation::isName()`).
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
     * The requirement the operation's step-up must meet, or `null` when neither
     * the package nor the application names it.
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
     * The first factor the application declares its guard uses, or `null` when
     * it declares none.
     *
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
     * Read every setting, failing closed on the first that is malformed.
     *
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
     * One entry of the `freshness` block as a requirement: seconds for an
     * additional verification within that age, or a serialised requirement
     * asking for at least one part, every part within a day.
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
     * A limit from the `limits` block, from 1 to its greatest value.
     *
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
