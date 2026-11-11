<?php

declare(strict_types = 1);

namespace Tests\Integration\Secrets;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * A TOTP secret survives an `app.key` rotation while its key stays in
 * `APP_PREVIOUS_KEYS`, and not once the key is dropped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Factor::class)]
final class KeyRotationTest extends TestCase
{
    use RefreshDatabase;

    /** @var string 160-bit TOTP secret. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /** @var string RFC 4648 base32 alphabet. */
    private const string BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASecretEncryptedUnderAPreviousKeyVerifies(): void
    {
        $previous = self::newKey();

        $this->useKeys($previous);

        $factor = $this->totpFactor();

        $this->useKeys(self::newKey(), $previous);

        $reloaded = Factor::query()->findOrFail($factor->id);

        self::assertSame(self::SECRET, $reloaded->secret);

        $binding = new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::STEP_UP);

        self::assertSame(CodeCheck::ACCEPTED, Mfa::driver('totp')->verify($reloaded, self::totp(self::SECRET, time()), $binding));
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheSecretIsStoredEncrypted(): void
    {
        $this->useKeys(self::newKey());

        $factor = $this->totpFactor();

        $stored = $factor->getConnection()->table($factor->getTable())->where('id', $factor->id)->value('secret');

        self::assertIsString($stored);
        self::assertStringNotContainsString(self::SECRET, $stored);
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASecretUnderADroppedKeyDoesNotDecrypt(): void
    {
        $this->useKeys(self::newKey());

        $factor = $this->totpFactor();

        $this->useKeys(self::newKey());

        $reloaded = Factor::query()->findOrFail($factor->id);

        $this->expectException(DecryptException::class);

        self::fail((string) $reloaded->secret);
    }

    /**
     * @param  string  $key
     * @param  string  ...$previous
     * @return void
     */
    private function useKeys(string $key, string ...$previous): void
    {
        config()->set('app.key', $key);
        config()->set('app.previous_keys', $previous);

        $this->container()->forgetInstance('encrypter');

        Crypt::clearResolvedInstance('encrypter');
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function totpFactor(): Factor
    {
        $user = TestUser::create(['email' => 'rotation@example.test', 'mfa_enabled' => true]);

        $factor = new Factor([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => self::SECRET,
            'totp_algorithm'       => 'sha1',
            'totp_digits'          => 6,
            'totp_period'          => 30,
            'status'               => 'confirmed',
        ]);

        $factor->save();

        return $factor;
    }

    /**
     * @return string
     *
     * @throws \Random\RandomException
     */
    private static function newKey(): string
    {
        return 'base64:' . base64_encode(random_bytes(32));
    }

    /**
     * RFC 6238 with SHA-1, six digits and a 30-second period.
     *
     * @param  string  $secret
     * @param  int  $time
     * @return string
     */
    private static function totp(string $secret, int $time): string
    {
        $hash   = hash_hmac('sha1', pack('J', intdiv($time, 30)), self::base32Decode($secret), true);
        $offset = ord($hash[19]) & 0x0F;
        $value  = ((ord($hash[$offset]) & 0x7F) << 24)
            | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8)
            | ord($hash[$offset + 3]);

        return str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);
    }

    /**
     * @param  string  $encoded
     * @return string
     */
    private static function base32Decode(string $encoded): string
    {
        $bits = '';

        foreach (str_split($encoded) as $character) {
            $bits .= str_pad(decbin((int) strpos(self::BASE32, $character)), 5, '0', STR_PAD_LEFT);
        }

        $bits  = substr($bits, 0, intdiv(strlen($bits), 8) * 8);
        $bytes = '';

        foreach (str_split($bits, 8) as $byte) {
            $bytes .= chr((int) bindec($byte));
        }

        return $bytes;
    }
}
