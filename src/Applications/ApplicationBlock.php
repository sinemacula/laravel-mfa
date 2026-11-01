<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Applications;

use Illuminate\Contracts\Config\Repository;

/**
 * Reads one application's raw block from `mfa.applications.{name}` for
 * `ApplicationSettings`, on every call: the block and its nested blocks, each
 * refused when it is not an array or holds a key it does not know, its
 * `enabled` flags, its lists of factor type names, and the full key of each
 * setting for the messages that name it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApplicationBlock
{
    /** @var array<string, list<string>|null> The keys an application block may hold, and the keys each nested block may hold. */
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
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $name
     */
    public function __construct(

        /** Configuration the block is read from on every call. */
        private Repository $config,

        /** The application's name: its key in `mfa.applications`. */
        private string $name,
    ) {}

    /**
     * The application's block, refusing one that is not an array or holds a key
     * the block does not know; an application with no block has every default.
     *
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    public function all(): array
    {
        $applications = $this->config->get(ApplicationSettings::APPLICATIONS);
        $settings     = is_array($applications) ? $applications[$this->name] ?? [] : [];

        if (!is_array($settings)) {
            throw new \InvalidArgumentException(sprintf('%s must be an array.', $this->key()));
        }

        $unknown = array_diff(array_map(strval(...), array_keys($settings)), array_keys(self::KEYS));

        if ($unknown !== []) {
            throw new \InvalidArgumentException(sprintf('%s holds keys it does not know: %s.', $this->key(), implode(', ', $unknown)));
        }

        return $settings;
    }

    /**
     * A nested block of the application's settings, refusing one that is not an
     * array or holds a key it does not know.
     *
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

        $unknown = array_diff(array_map(strval(...), array_keys($block)), self::KEYS[$name] ?? []);

        if ($unknown !== []) {
            throw new \InvalidArgumentException(sprintf('%s holds keys it does not know: %s.', $this->key($name), implode(', ', $unknown)));
        }

        return $block;
    }

    /**
     * Whether the `enabled` flag of a nested block is on, `false` when it is
     * not set.
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
     * The value as a list of distinct factor type names, refusing anything else
     * under the setting's key.
     *
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
     * The full key of a setting of the application, or of its block.
     *
     * @param  ?string  $setting
     * @return string
     */
    public function key(?string $setting = null): string
    {
        return ApplicationSettings::APPLICATIONS . '.' . $this->name . ($setting === null ? '' : '.' . $setting);
    }
}
