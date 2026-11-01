<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

/**
 * Reads the typed fields of a value's serialised form back, so a value read
 * from a session, a cache or JSON is refused rather than half-built when a
 * field is missing or of another type.
 *
 * Every refusal is an `InvalidArgumentException` naming the field and what it
 * belongs to. A nullable reader treats a missing field as `null`, and a field
 * the form does not know is refused, so a mistyped key is never read as a
 * missing one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SerializedFields
{
    /**
     * Constructor.
     *
     * @param  array<array-key, mixed>  $data
     * @param  string  $subject
     */
    public function __construct(

        /** The serialised form. */
        private array $data,

        /** What the form is of, as the messages name it, such as `a serialised proof`. */
        private string $subject,
    ) {}

    /**
     * Refuse any field other than the given ones.
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
     * Read a field that must be a string.
     *
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
     * Read a field that must be a string or null.
     *
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
     * Read a field that must be a boolean or null.
     *
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
     * Read a field that must be an integer.
     *
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
     * Read a field that must be an integer or null.
     *
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
     * Read a field that must be an array.
     *
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
     * Read a field that must be an array or null.
     *
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
     * Read a field that must be one of a string-backed enum's values.
     *
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
     * Read a field that must be one of a string-backed enum's values, or null.
     *
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
     * The enum case a field's value names.
     *
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
     * The refusal of a field.
     *
     * @param  string  $key
     * @param  string  $problem
     * @return \InvalidArgumentException
     */
    private function refuse(string $key, string $problem): \InvalidArgumentException
    {
        return new \InvalidArgumentException(sprintf('The [%s] field of %s %s.', $key, $this->subject, $problem));
    }
}
