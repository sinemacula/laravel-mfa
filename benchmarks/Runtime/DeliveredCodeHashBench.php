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
 * Keyed hashing of delivered codes, shared by the email and SMS drivers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DeliveredCodeHashBench
{
    /** @var string */
    private const string CODE = '123456';

    /** @var \SineMacula\Laravel\Mfa\Codes\CodeKeys */
    private CodeKeys $keys;

    /** @var \SineMacula\Laravel\Mfa\Proofs\ProofBinding */
    private ProofBinding $binding;

    /**
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
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchCodeHash(): void
    {
        $this->hash(self::CODE);
    }

    /**
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchSessionDigest(): void
    {
        $this->keys->session('session-id');
    }

    /**
     * @param  string  $code
     * @return string
     */
    private function hash(#[\SensitiveParameter] string $code): string
    {
        return $this->keys->code('01jbench0000000000000000000', 1, 'factor-id', $this->binding, $code);
    }
}
