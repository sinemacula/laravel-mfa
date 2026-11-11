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
 * A redemption checks every unused code, so its time follows the unused count,
 * not the match position; a few cases repeat at the default bcrypt cost.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RecoveryCodeBench
{
    /** @var string Shipped alphabet. */
    private const string ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

    /** @var int Default set size. */
    private const int SET_SIZE = 10;

    /** @var string Matches none of the set. */
    private const string MISS = 'ZZZZ-ZZZZ-ZZZZ';

    /** @var \Illuminate\Hashing\BcryptHasher */
    private BcryptHasher $hasher;

    /** @var list<string> Unused codes' hashes. */
    private array $hashes = [];

    /** @var string As a person might type it. */
    private string $submitted = '';

    /**
     * @return void
     */
    public function __construct()
    {
        $this->hasher = new BcryptHasher(['rounds' => 4]);
    }

    /**
     * Unused count and the submitted index, `null` for a miss.
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
     * Enough to show the cost follows the unused count, not the position.
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
     * One revolution, as each check costs as much as a password check.
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
     * Hash the unused codes and prove the index `find()` returns.
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
