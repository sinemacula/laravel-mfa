<?php

declare(strict_types = 1);

namespace Tests\Fixtures\RecoveryCodes;

use Illuminate\Contracts\Hashing\Hasher;

/**
 * A hasher that counts its checks and records what each was given, so a test
 * can prove how much work a redemption did.
 *
 * Given a hasher, it hands every call on to it; without one, it hashes by
 * prefixing the value, which is enough for a test that only compares. A hook,
 * when set, runs before the check it is set for (the first by default), once: a
 * test stands a concurrent request in there, which then runs while the
 * redemption it interrupts has read the set and is part-way through checking
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingHasher implements Hasher
{
    /** @var string What the fake hashing prefixes a value with. */
    public const string PREFIX = 'counted:';

    /** @var list<string> The value each check was given, in order. */
    public array $checked = [];

    /** @var ?\Closure(): void Run once, before the check it is set for. */
    private ?\Closure $hook = null;

    /** @var int The check, counting from one, the hook runs before. */
    private int $hookAt = 1;

    /**
     * Constructor.
     *
     * @param  ?\Illuminate\Contracts\Hashing\Hasher  $inner
     */
    public function __construct(

        /** The hasher every call is handed to, or null to hash by prefixing. */
        private readonly ?Hasher $inner = null,
    ) {}

    /**
     * Run the hook once, before the given check.
     *
     * @param  \Closure(): void  $hook
     * @param  int  $at
     * @return void
     */
    public function before(\Closure $hook, int $at = 1): void
    {
        $this->hook   = $hook;
        $this->hookAt = $at;
    }

    /**
     * How many checks were made.
     *
     * @return int
     */
    public function checks(): int
    {
        return count($this->checked);
    }

    /**
     * Get information about the given hashed value.
     *
     * @param  mixed  $hashedValue
     * @return array<string, mixed>
     */
    #[\Override]
    public function info(mixed $hashedValue): array
    {
        return $this->inner?->info($hashedValue) ?? ['algo' => null, 'algoName' => 'counted', 'options' => []];
    }

    /**
     * Hash the given value.
     *
     * @param  mixed  $value
     * @param  array<mixed>  $options
     * @return string
     */
    #[\Override]
    public function make(#[\SensitiveParameter] mixed $value, array $options = []): string
    {
        return $this->inner?->make($value, $options) ?? self::PREFIX . self::text($value);
    }

    /**
     * Count and record the check, run the hook when it is due, and check the
     * value against the hash.
     *
     * @param  mixed  $value
     * @param  mixed  $hashedValue
     * @param  array<mixed>  $options
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function check(#[\SensitiveParameter] mixed $value, mixed $hashedValue, array $options = []): bool
    {
        $this->checked[] = self::text($value);

        if ($this->hook !== null && count($this->checked) === $this->hookAt) {

            $hook       = $this->hook;
            $this->hook = null;

            $hook();
        }

        return $this->inner?->check($value, $hashedValue, $options) ?? $hashedValue === self::PREFIX . self::text($value);
    }

    /**
     * Whether the hash needs rehashing: never.
     *
     * @param  mixed  $hashedValue
     * @param  array<mixed>  $options
     * @return bool
     */
    #[\Override]
    public function needsRehash(mixed $hashedValue, array $options = []): bool
    {
        return false;
    }

    /**
     * The value as text: a hasher is only ever given a string, which the
     * contract leaves untyped.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function text(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }
}
