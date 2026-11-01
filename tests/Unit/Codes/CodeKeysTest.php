<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\CodeKeys;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Unit tests for `CodeKeys`: a code's hash is keyed and bound to every part of
 * its challenge and binding, the session is stored as a keyed digest, and both
 * need the application key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeKeys::class)]
final class CodeKeysTest extends TestCase
{
    /** @var string The application key the keys derive from. */
    private const string APP_KEY = 'base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=';

    /** @var string A code. */
    private const string CODE = '123456';

    /**
     * A code's hash is 64 hexadecimal characters, the same each time, and
     * neither the code nor its plain hash.
     *
     * @return void
     */
    public function testACodeHashIsAKeyedDigest(): void
    {
        $hash = self::keys()->code('challenge', 1, 'factor', self::binding(), self::CODE);

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
        self::assertSame($hash, self::keys()->code('challenge', 1, 'factor', self::binding(), self::CODE));
        self::assertNotSame(hash('sha256', self::CODE), $hash);
        self::assertNotSame($hash, self::keys('base64:' . base64_encode(str_repeat('x', 32)))->code('challenge', 1, 'factor', self::binding(), self::CODE));
    }

    /**
     * Rows of a hash computed with one part changed.
     *
     * @return iterable<string, array{\Closure(\SineMacula\Laravel\Mfa\Codes\CodeKeys): string}>
     */
    public static function changedParts(): iterable
    {
        yield 'challenge' => [static fn (CodeKeys $keys): string => $keys->code('other', 1, 'factor', self::binding(), self::CODE)];
        yield 'issue' => [static fn (CodeKeys $keys): string => $keys->code('challenge', 2, 'factor', self::binding(), self::CODE)];
        yield 'factor' => [static fn (CodeKeys $keys): string => $keys->code('challenge', 1, 'other', self::binding(), self::CODE)];
        yield 'identity type' => [static fn (CodeKeys $keys): string => $keys->code('challenge', 1, 'factor', self::binding(type: 'App\Admin'), self::CODE)];
        yield 'identity key' => [static fn (CodeKeys $keys): string => $keys->code('challenge', 1, 'factor', self::binding(key: '2'), self::CODE)];
        yield 'application' => [static fn (CodeKeys $keys): string => $keys->code('challenge', 1, 'factor', self::binding(application: 'admin'), self::CODE)];
        yield 'session' => [static fn (CodeKeys $keys): string => $keys->code('challenge', 1, 'factor', self::binding(session: 'other'), self::CODE)];
        yield 'purpose' => [static fn (CodeKeys $keys): string => $keys->code('challenge', 1, 'factor', self::binding(purpose: Purpose::STEP_UP), self::CODE)];
        yield 'code' => [static fn (CodeKeys $keys): string => $keys->code('challenge', 1, 'factor', self::binding(), '654321')];
    }

    /**
     * Changing any one part of the challenge, the binding or the code changes
     * the hash, so a code matches nothing it was not issued for.
     *
     * @param  \Closure(\SineMacula\Laravel\Mfa\Codes\CodeKeys): string  $hash
     * @return void
     */
    #[DataProvider('changedParts')]
    public function testEveryPartIsBoundIntoTheHash(\Closure $hash): void
    {
        self::assertNotSame(self::keys()->code('challenge', 1, 'factor', self::binding(), self::CODE), $hash(self::keys()));
    }

    /**
     * A session is stored as a keyed digest of its id, never the id, and the
     * digest is not the code key's.
     *
     * @return void
     */
    public function testASessionIsStoredAsAKeyedDigest(): void
    {
        $digest = self::keys()->session('session-id');

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $digest);
        self::assertSame($digest, self::keys()->session('session-id'));
        self::assertNotSame($digest, self::keys()->session('other-session'));
        self::assertNotSame(hash('sha256', 'session-id'), $digest);
        self::assertNotSame($digest, self::keys('base64:' . base64_encode(str_repeat('x', 32)))->session('session-id'));
    }

    /**
     * Rows of an application key that is not set.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function missingKeys(): iterable
    {
        yield 'null' => [null];
        yield 'empty' => [''];
        yield 'not a string' => [['key']];
    }

    /**
     * Without an application key nothing is hashed, and the check says so.
     *
     * @param  mixed  $key
     * @return void
     */
    #[DataProvider('missingKeys')]
    public function testNothingIsHashedWithoutAnApplicationKey(mixed $key): void
    {
        $keys = new CodeKeys(new Repository(['app' => ['key' => $key]]));

        $calls = [
            static fn (CodeKeys $keys): mixed => $keys->code('challenge', 1, 'factor', self::binding(), self::CODE),
            static fn (CodeKeys $keys): mixed => $keys->session('session-id'),
            static function (CodeKeys $keys): void {
                $keys->validate();
            },
        ];

        foreach ($calls as $call) {

            try {
                $call($keys);
                self::fail('Expected the missing key to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('Delivered codes are hashed with a key derived from the application key; set app.key.', $exception->getMessage());
            }
        }
    }

    /**
     * A set application key validates.
     *
     * @return void
     */
    public function testASetApplicationKeyValidates(): void
    {
        $this->expectNotToPerformAssertions();

        self::keys()->validate();
    }

    /**
     * The keys over an application key.
     *
     * @param  string  $key
     * @return \SineMacula\Laravel\Mfa\Codes\CodeKeys
     */
    private static function keys(string $key = self::APP_KEY): CodeKeys
    {
        return new CodeKeys(new Repository(['app' => ['key' => $key]]));
    }

    /**
     * A binding, with any part changed.
     *
     * @param  string  $type
     * @param  string  $key
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(string $type = 'App\User', string $key = '1', string $application = 'web', string $session = 'session-id', Purpose $purpose = Purpose::SIGN_IN): ProofBinding
    {
        return new ProofBinding($type, $key, $application, $session, $purpose);
    }
}
