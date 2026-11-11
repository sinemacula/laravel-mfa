<?php

declare(strict_types = 1);

namespace Tests\Fixtures\RecoveryCodes;

use Illuminate\Contracts\Hashing\Hasher;

/**
 * Records every check, so a test can prove how much work a redemption did.
 * Without an inner hasher it hashes by prefixing. A hook set with `before()`
 * runs once, so a concurrent request can interrupt a redemption mid-check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingHasher implements Hasher
{
    /** @var string */
    public const string PREFIX = 'counted:';

    /** @var list<string> */
    public array $checked = [];

    /** @var ?\Closure(): void */
    private ?\Closure $hook = null;

    /** @var int Counted from one. */
    private int $hookAt = 1;

    /**
     * @param  ?\Illuminate\Contracts\Hashing\Hasher  $inner
     */
    public function __construct(

        /** `null` hashes by prefixing. */
        private readonly ?Hasher $inner = null,
    ) {}

    /**
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
     * @return int
     */
    public function checks(): int
    {
        return count($this->checked);
    }

    /**
     * @param  string  $hashedValue
     * @return array<string, mixed>
     */
    #[\Override]
    public function info(mixed $hashedValue): array
    {
        return $this->inner?->info($hashedValue) ?? ['algo' => null, 'algoName' => 'counted', 'options' => []];
    }

    /**
     * @param  string  $value
     * @param  array<mixed>  $options
     * @return string
     */
    #[\Override]
    public function make(#[\SensitiveParameter] mixed $value, array $options = []): string
    {
        return $this->inner?->make($value, $options) ?? self::PREFIX . $value;
    }

    /**
     * @param  string  $value
     * @param  string  $hashedValue
     * @param  array<mixed>  $options
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function check(#[\SensitiveParameter] mixed $value, mixed $hashedValue, array $options = []): bool
    {
        $this->checked[] = $value;

        if ($this->hook !== null && count($this->checked) === $this->hookAt) {

            $hook       = $this->hook;
            $this->hook = null;

            $hook();
        }

        return $this->inner?->check($value, $hashedValue, $options) ?? $hashedValue === self::PREFIX . $value;
    }

    /**
     * @param  string  $hashedValue
     * @param  array<mixed>  $options
     * @return bool
     */
    #[\Override]
    public function needsRehash(mixed $hashedValue, array $options = []): bool
    {
        return false;
    }
}
