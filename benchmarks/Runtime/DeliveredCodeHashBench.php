<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchOutcome;
use Illuminate\Config\Repository;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use SineMacula\Laravel\Mfa\Codes\CodeKeys;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Hot-path benchmarks for the keyed hashing of delivered codes: what a send and
 * a check compute besides their statements, the same for the email and SMS
 * drivers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DeliveredCodeHashBench
{
    /** @var string The code hashed. */
    private const string CODE = '123456';

    /** @var \SineMacula\Laravel\Mfa\Codes\CodeKeys The keys, over a fixed application key. */
    private CodeKeys $keys;

    /** @var \SineMacula\Laravel\Mfa\Proofs\ProofBinding The binding every code is hashed for. */
    private ProofBinding $binding;

    /**
     * Build the keys and the binding the benches reuse across iterations, and
     * prove a hash follows the code it is given and a digest the session.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function __construct()
    {
        $this->keys    = new CodeKeys(new Repository(['app' => ['key' => 'base64:' . base64_encode(str_repeat('k', 32))]]));
        $this->binding = new ProofBinding('App\Models\User', '42', 'web', 'session-id', Purpose::SIGN_IN);

        $hash = $this->hash(self::CODE);

        BenchOutcome::assert('code hash', $hash === $this->hash(self::CODE) && $hash !== $this->hash('654321'));
        BenchOutcome::assert('session digest', $this->keys->session('session-id') !== $this->keys->session('other-session-id'));
    }

    /**
     * Measure the cost of hashing a code for its challenge and binding.
     *
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchCodeHash(): void
    {
        $this->hash(self::CODE);
    }

    /**
     * Measure the cost of the session digest a challenge is looked up by.
     *
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchSessionDigest(): void
    {
        $this->keys->session('session-id');
    }

    /**
     * The code's hash, for one challenge and binding.
     *
     * @param  string  $code
     * @return string
     */
    private function hash(#[\SensitiveParameter] string $code): string
    {
        return $this->keys->code('01jbench0000000000000000000', 1, 'factor-id', $this->binding, $code);
    }
}
