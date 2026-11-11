<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

/**
 * Typed reads of a serialised form, refusing a missing or mistyped field rather
 * than half-building the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SerializedFields
{
    /**
     * @param  array<array-key, mixed>  $data
     * @param  string  $subject
     */
    public function __construct(

        /** The serialised form. */
        private array $data,

        /** Named in messages, such as `a serialised proof`. */
        private string $subject,
    ) {}

    /**
     * So a mistyped key is never read as a missing one.
     *
     * @param  string  ...$known
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refuseUnknown(string ...$known): void
    {
        foreach (array_keys($this->data) as $key) {
            if (!in_array($key, $known, true)) {
                throw $this->refuse((string) $key, 'is not a known field');
            }
        }
    }

    /**
     * @param  string  $key
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function string(string $key): string
    {
        $value = $this->data[$key] ?? null;

        if (!is_string($value)) {
            throw $this->refuse($key, 'must be a string');
        }

        return $value;
    }

    /**
     * @param  string  $key
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function nullableString(string $key): ?string
    {
        $value = $this->data[$key] ?? null;

        if ($value !== null && !is_string($value)) {
            throw $this->refuse($key, 'must be a string or null');
        }

        return $value;
    }

    /**
     * @imperative
     *
     * @param  string  $key
     * @return ?bool
     *
     * @throws \InvalidArgumentException
     */
    public function nullableBool(string $key): ?bool
    {
        $value = $this->data[$key] ?? null;

        if ($value !== null && !is_bool($value)) {
            throw $this->refuse($key, 'must be a boolean or null');
        }

        return $value;
    }

    /**
     * @param  string  $key
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function int(string $key): int
    {
        $value = $this->data[$key] ?? null;

        if (!is_int($value)) {
            throw $this->refuse($key, 'must be an integer');
        }

        return $value;
    }

    /**
     * @param  string  $key
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    public function nullableInt(string $key): ?int
    {
        $value = $this->data[$key] ?? null;

        if ($value !== null && !is_int($value)) {
            throw $this->refuse($key, 'must be an integer or null');
        }

        return $value;
    }

    /**
     * @param  string  $key
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    public function array(string $key): array
    {
        $value = $this->data[$key] ?? null;

        if (!is_array($value)) {
            throw $this->refuse($key, 'must be an array');
        }

        return $value;
    }

    /**
     * @param  string  $key
     * @return ?array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    public function nullableArray(string $key): ?array
    {
        $value = $this->data[$key] ?? null;

        if ($value !== null && !is_array($value)) {
            throw $this->refuse($key, 'must be an array or null');
        }

        return $value;
    }

    /**
     * @template T of \BackedEnum
     *
     * @param  string  $key
     * @param  class-string<T>  $enum
     * @return T
     *
     * @throws \InvalidArgumentException
     */
    public function enum(string $key, string $enum): \BackedEnum
    {
        return $this->toEnum($key, $this->string($key), $enum);
    }

    /**
     * @template T of \BackedEnum
     *
     * @param  string  $key
     * @param  class-string<T>  $enum
     * @return ?T
     *
     * @throws \InvalidArgumentException
     */
    public function nullableEnum(string $key, string $enum): ?\BackedEnum
    {
        $value = $this->nullableString($key);

        return $value === null ? null : $this->toEnum($key, $value, $enum);
    }

    /**
     * @template T of \BackedEnum
     *
     * @param  string  $key
     * @param  string  $value
     * @param  class-string<T>  $enum
     * @return T
     *
     * @throws \InvalidArgumentException
     */
    private function toEnum(string $key, string $value, string $enum): \BackedEnum
    {
        return $enum::tryFrom($value) ?? throw $this->refuse($key, 'is not a known value');
    }

    /**
     * @param  string  $key
     * @param  string  $problem
     * @return \InvalidArgumentException
     */
    private function refuse(string $key, string $problem): \InvalidArgumentException
    {
        return new \InvalidArgumentException(sprintf('The [%s] field of %s %s.', $key, $this->subject, $problem));
    }
}
