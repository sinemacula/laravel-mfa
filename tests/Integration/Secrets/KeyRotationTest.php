<?php

declare(strict_types = 1);

namespace Tests\Integration\Secrets;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests that a TOTP secret survives a rotation of the application key: a
 * secret encrypted under a key that is now listed in `APP_PREVIOUS_KEYS`
 * decrypts and verifies, and one under a key that is dropped does not.
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

    /** @var string A TOTP secret of 160 bits. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /** @var string The RFC 4648 base32 alphabet. */
    private const string BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * A secret encrypted under a key that is now a previous key decrypts, and
     * a code from it verifies.
     *
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
        self::assertTrue(Mfa::driver('totp')->verify($reloaded, self::totp(self::SECRET, time())));
    }

    /**
     * The stored secret is ciphertext, not the plaintext, under either key.
     *
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
     * A secret encrypted under a key that is dropped rather than kept as a
     * previous key no longer decrypts.
     *
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
     * Use the key, with the previous keys, for every encryption from now on.
     *
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
     * A confirmed TOTP factor holding the secret.
     *
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
     * A new application key.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private static function newKey(): string
    {
        return 'base64:' . base64_encode(random_bytes(32));
    }

    /**
     * The RFC 6238 code of the secret at the time, with SHA-1, six digits and
     * a 30 second period.
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
     * The bytes a base32 string encodes.
     *
     * @param  string  $encoded
     * @return string
     */
    private static function base32Decode(string $encoded): string
    {
        $bits = '';

        foreach (str_split($encoded) as $character) {
            $bits .= str_pad(decbin((int) strpos(self::BASE32, $character)), 5, '0', STR_PAD_LEFT);
        }

        $bytes = '';

        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $bytes .= chr((int) bindec($byte));
            }
        }

        return $bytes;
    }
}
