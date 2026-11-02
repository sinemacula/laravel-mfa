<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchOutcome;
use Illuminate\Hashing\BcryptHasher;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\ParamProviders;
use PhpBench\Attributes\Revs;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGenerator;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeMatcher;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeNormalizer;

/**
 * Recovery codes with no database: drawing a set, and the comparison a
 * redemption makes against a full, a partly used and an empty set, whichever
 * code matches and when none does.
 *
 * A redemption checks every unused code, so its time follows the unused count
 * and not the position of the match; these timings are measurements to show
 * that, not assertions. The matrix uses bcrypt at its cheapest cost and a few
 * cases repeat at the framework's default cost, where the hashing is what a
 * redemption spends; the figures scale with the application's own hashing cost.
 * The statements a redemption makes belong to the query budgets. Every case
 * proves at set-up the exact code `find()` returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RecoveryCodeBench
{
    /** @var string The shipped alphabet. */
    private const string ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

    /** @var int The default size of a set. */
    private const int SET_SIZE = 10;

    /** @var string A code submitted that matches none of the set. */
    private const string MISS = 'ZZZZ-ZZZZ-ZZZZ';

    /** @var \Illuminate\Hashing\BcryptHasher The hasher of the subject measured. */
    private BcryptHasher $hasher;

    /** @var list<string> The unused codes' hashes. */
    private array $hashes = [];

    /** @var string The code submitted, as a person might type it. */
    private string $submitted = '';

    /**
     * The sets compared against at the cheapest cost, by how many codes are
     * unused, and the index of the code submitted, `null` for a miss.
     *
     * @return iterable<string, array{unused: int, index: ?int}>
     */
    public function provideRedemptions(): iterable
    {
        foreach (['full' => self::SET_SIZE, 'partly used' => 5] as $set => $unused) {
            foreach (['first' => 0, 'middle' => intdiv($unused, 2), 'last' => $unused - 1, 'miss' => null] as $position => $index) {
                yield $set . ', ' . $position => ['unused' => $unused, 'index' => $index];
            }
        }

        yield 'empty' => ['unused' => 0, 'index' => null];
    }

    /**
     * The sets compared against at the framework's default cost: enough to show
     * the cost follows the unused count and not the position.
     *
     * @return iterable<string, array{unused: int, index: ?int}>
     */
    public function provideRedemptionsAtDefaultCost(): iterable
    {
        yield 'full, first' => ['unused' => self::SET_SIZE, 'index' => 0];
        yield 'full, last' => ['unused' => self::SET_SIZE, 'index' => self::SET_SIZE - 1];
        yield 'full, miss' => ['unused' => self::SET_SIZE, 'index' => null];
        yield 'partly used, miss' => ['unused' => 5, 'index' => null];
    }

    /**
     * Draw and hash a set at the cheapest cost and prove the case.
     *
     * @param  array{unused: int, index: ?int}  $params
     * @return void
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function arrange(array $params): void
    {
        $this->arrangeWith(new BcryptHasher(['rounds' => 4]), $params);
    }

    /**
     * Draw and hash a set at the framework's default cost and prove the case.
     *
     * @param  array{unused: int, index: ?int}  $params
     * @return void
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function arrangeAtDefaultCost(array $params): void
    {
        $this->arrangeWith(new BcryptHasher, $params);
    }

    /**
     * Measure the comparison of a submitted code, normalised, against the
     * unused codes of a set.
     *
     * @return void
     */
    #[BeforeMethods('arrange')]
    #[Iterations(3)]
    #[ParamProviders('provideRedemptions')]
    #[Revs(10)]
    public function benchRedeem(): void
    {
        RecoveryCodeMatcher::find($this->hasher, $this->hashes, RecoveryCodeNormalizer::normalize($this->submitted));
    }

    /**
     * Measure the same comparison at the framework's default cost, once in each
     * iteration, as each check is as slow as checking a password.
     *
     * @return void
     */
    #[BeforeMethods('arrangeAtDefaultCost')]
    #[Iterations(3)]
    #[ParamProviders('provideRedemptionsAtDefaultCost')]
    #[Revs(1)]
    public function benchRedeemAtDefaultCost(): void
    {
        RecoveryCodeMatcher::find($this->hasher, $this->hashes, RecoveryCodeNormalizer::normalize($this->submitted));
    }

    /**
     * Measure drawing a set of the default size.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchGenerate(): void
    {
        (new RecoveryCodeGenerator)->generate(self::SET_SIZE, 12, self::ALPHABET);
    }

    /**
     * Draw the case's set, hash its unused codes and prove the index `find()`
     * returns, and that a miss is none of the codes drawn.
     *
     * @param  \Illuminate\Hashing\BcryptHasher  $hasher
     * @param  array{unused: int, index: ?int}  $params
     * @return void
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function arrangeWith(BcryptHasher $hasher, array $params): void
    {
        $codes = array_slice((new RecoveryCodeGenerator)->generate(self::SET_SIZE, 12, self::ALPHABET), 0, $params['unused']);

        $this->hasher    = $hasher;
        $this->hashes    = array_map($hasher->make(...), $codes);
        $this->submitted = $params['index'] === null ? self::MISS : strtolower($codes[$params['index']]);

        BenchOutcome::assert('recovery code', RecoveryCodeMatcher::find($hasher, $this->hashes, RecoveryCodeNormalizer::normalize($this->submitted)) === $params['index']);
        BenchOutcome::assert('recovery code', $params['index'] !== null || !in_array(RecoveryCodeNormalizer::normalize(self::MISS), $codes, true));
    }
}
