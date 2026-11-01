<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Illuminate\Hashing\BcryptHasher;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\ParamProviders;
use PhpBench\Attributes\Revs;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGenerator;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeMatcher;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeNormalizer;

/**
 * Hot-path benchmarks for recovery codes: drawing a set, and the comparison a
 * redemption makes against a full, a partly used and an empty set, whichever
 * code matches and when none does.
 *
 * A redemption checks every unused code, so its time follows the unused count
 * and not the position of the match; these timings are measurements to show
 * that, not assertions. The hasher is bcrypt at its cheapest cost, so the
 * figures scale with the application's own hashing cost; the statements a
 * redemption makes belong to the performance suite, not here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RecoveryCodeBench
{
    /** @var string The shipped alphabet. */
    private const string ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

    /** @var \Illuminate\Hashing\BcryptHasher The hasher, at bcrypt's cheapest cost. */
    private BcryptHasher $hasher;

    /** @var list<string> The codes of a full set. */
    private array $codes;

    /** @var list<string> The hashes of a full set. */
    private array $hashes;

    /**
     * Draw and hash a full set once per benchmark subject lifetime.
     *
     * @return void
     */
    public function __construct()
    {
        $this->hasher = new BcryptHasher(['rounds' => 4]);
        $this->codes  = (new RecoveryCodeGenerator)->generate(10, 12, self::ALPHABET);
        $this->hashes = array_map(fn (string $code): string => $this->hasher->make($code), $this->codes);
    }

    /**
     * The sets compared against, by how many codes are unused, and the code
     * submitted, by where its match sits.
     *
     * @return iterable<string, array{unused: int, submitted: string}>
     */
    public function provideRedemptions(): iterable
    {
        foreach (['full' => 10, 'partly used' => 5, 'empty' => 0] as $set => $unused) {
            foreach (['first' => 0, 'middle' => intdiv($unused, 2), 'last' => max($unused - 1, 0), 'miss' => null] as $position => $index) {
                yield $set . ', ' . $position => ['unused' => $unused, 'submitted' => $index === null ? 'ZZZZ-ZZZZ-ZZZZ' : 'index:' . $index];
            }
        }
    }

    /**
     * Measure the comparison of a submitted code, normalised, against the
     * unused codes of a set.
     *
     * @param  array{unused: int, submitted: string}  $params
     * @return void
     */
    #[Iterations(3)]
    #[ParamProviders('provideRedemptions')]
    #[Revs(10)]
    public function benchRedeem(array $params): void
    {
        $hashes    = array_slice($this->hashes, 0, $params['unused']);
        $submitted = str_starts_with($params['submitted'], 'index:')
            ? $this->codes[(int) substr($params['submitted'], 6)]
            : $params['submitted'];

        RecoveryCodeMatcher::find($this->hasher, $hashes, RecoveryCodeNormalizer::normalize(strtolower($submitted)));
    }

    /**
     * Measure drawing a set of the default size.
     *
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchGenerate(): void
    {
        (new RecoveryCodeGenerator)->generate(10, 12, self::ALPHABET);
    }
}
