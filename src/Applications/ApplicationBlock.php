<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Applications;

use Illuminate\Contracts\Config\Repository;

/**
 * Reads one application's raw block from `mfa.applications.{name}` on every
 * call, refusing anything malformed or unknown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApplicationBlock
{
    /** @var array<string, list<string>|null> Known keys, and each nested block's known keys. */
    private const array KEYS = [
        'types'          => null,
        'requirement'    => null,
        'recovery_codes' => ['enabled', 'level'],
        'bootstrap'      => ['enabled', 'types'],
        'limits'         => ['confirmed_per_type', 'confirmed', 'pending'],
        'totp_window'    => null,
        'freshness'      => null,
        'first_factor'   => ['method', 'channel'],
    ];

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $name
     */
    public function __construct(

        /** Read on every call. */
        private Repository $config,

        /** Its key in `mfa.applications`. */
        private string $name,
    ) {}

    /**
     * An application with no block has every default.
     *
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    public function all(): array
    {
        $applications = $this->config->get(ApplicationSettings::APPLICATIONS) ?? [];

        if (!is_array($applications)) {
            throw new \InvalidArgumentException(sprintf('%s must be an array of application blocks keyed by name.', ApplicationSettings::APPLICATIONS));
        }

        $settings = $applications[$this->name] ?? [];

        if (!is_array($settings)) {
            throw new \InvalidArgumentException(sprintf('%s must be an array.', $this->key()));
        }

        $unknown = array_diff(array_keys($settings), array_keys(self::KEYS));

        if ($unknown !== []) {
            throw new \InvalidArgumentException(sprintf('%s holds keys it does not know: %s.', $this->key(), implode(', ', $unknown)));
        }

        return $settings;
    }

    /**
     * @param  string  $name
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    public function nested(string $name): array
    {
        $block = $this->all()[$name] ?? [];

        if (!is_array($block)) {
            throw new \InvalidArgumentException(sprintf('%s must be an array.', $this->key($name)));
        }

        $unknown = array_diff(array_keys($block), self::KEYS[$name] ?? []);

        if ($unknown !== []) {
            throw new \InvalidArgumentException(sprintf('%s holds keys it does not know: %s.', $this->key($name), implode(', ', $unknown)));
        }

        return $block;
    }

    /**
     * Off when not set.
     *
     * @param  string  $name
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isEnabled(string $name): bool
    {
        $enabled = $this->nested($name)['enabled'] ?? false;

        if (!is_bool($enabled)) {
            throw new \InvalidArgumentException(sprintf('%s must be true or false.', $this->key($name . '.enabled')));
        }

        return $enabled;
    }

    /**
     * @param  string  $name
     * @param  mixed  $value
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function names(string $name, mixed $value): array
    {
        if (!is_array($value) || !array_is_list($value) || array_unique($value, SORT_REGULAR) !== $value) {
            throw new \InvalidArgumentException(sprintf('%s must be a list of distinct factor type names.', $this->key($name)));
        }

        foreach ($value as $type) {

            if (!is_string($type) || trim($type) === '') {
                throw new \InvalidArgumentException(sprintf('%s must be a list of distinct factor type names.', $this->key($name)));
            }
        }

        return $value;
    }

    /**
     * @param  ?string  $setting
     * @return string
     */
    public function key(?string $setting = null): string
    {
        return ApplicationSettings::APPLICATIONS . '.' . $this->name . ($setting === null ? '' : '.' . $setting);
    }
}
