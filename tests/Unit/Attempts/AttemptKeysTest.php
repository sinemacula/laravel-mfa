<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptKeys::class)]
final class AttemptKeysTest extends TestCase
{
    /** @var string An application key. */
    private const string APP_KEY = 'base64:2fl+Ktvkfl+Fuz4Qp/A75G2RTiWVA/ZoKZvp6fiiM10=';

    /**
     * The same for the same subject, and apart from a plain digest of the
     * subject.
     *
     * @return void
     */
    public function testAKeyIsAKeyedDigestOfTheScopeAndSubject(): void
    {
        $keys = self::keys(self::APP_KEY);

        $secret   = hash_hmac('sha256', 'sinemacula/laravel-mfa attempt throttles', self::APP_KEY, true);
        $expected = hash_hmac('sha256', implode("\0", ['identity', 'App\Models\User', '1']), $secret);

        self::assertSame($expected, $keys->identity('App\Models\User', '1'));
        self::assertSame($keys->identity('App\Models\User', '1'), $keys->identity('App\Models\User', '1'));
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $keys->ip('192.0.2.1'));
        self::assertNotSame(hash('sha256', '192.0.2.1'), $keys->ip('192.0.2.1'));
    }

    /**
     * The same subject in another scope or identity type, and another subject
     * in the same scope, count apart.
     *
     * @return void
     */
    public function testScopesAndSubjectsAreKeptApart(): void
    {
        $keys = self::keys(self::APP_KEY);

        $digests = [
            $keys->identity('App\Models\User', '1'),
            $keys->identity('App\Models\Admin', '1'),
            $keys->identity('App\Models\User', '2'),
            $keys->ip('1'),
            $keys->ip('192.0.2.1'),
            $keys->ip('198.51.100.7'),
        ];

        self::assertSame($digests, array_values(array_unique($digests)));
    }

    /**
     * So rotating it starts every throttle afresh.
     *
     * @return void
     */
    public function testAnotherApplicationKeyGivesAnotherKey(): void
    {
        self::assertNotSame(self::keys(self::APP_KEY)->ip('192.0.2.1'), self::keys('base64:another')->ip('192.0.2.1'));
    }

    /**
     * Without an application key there is nothing to key the rows with.
     *
     * @return void
     */
    public function testAMissingApplicationKeyIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The attempt throttles key their rows with the application key; set `app.key`.');

        self::keys('')->ip('192.0.2.1');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function addresses(): iterable
    {
        yield 'an IPv4 address' => ['192.0.2.1', '192.0.2.1'];
        yield 'an IPv4-mapped IPv6 address' => ['::ffff:192.0.2.1', '192.0.2.1'];
        yield 'a NAT64 address' => ['64:ff9b::c000:201', '192.0.2.1'];
        yield 'an IPv6 address' => ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'];
        yield 'another address in the same /64' => ['2001:db8:1:2:ffff:ffff:ffff:ffff', '2001:db8:1:2::/64'];
        yield 'something that is not an address' => ['unknown', 'unknown'];
    }

    /**
     * @param  string  $ip
     * @param  string  $canonical
     * @return void
     */
    #[DataProvider('addresses')]
    public function testAnAddressIsCountedByItsClient(string $ip, string $canonical): void
    {
        $keys = self::keys(self::APP_KEY);

        self::assertSame($canonical, AttemptKeys::canonicalIp($ip));
        self::assertSame($keys->ip($canonical), $keys->ip($ip));
    }

    /**
     * @param  string  $appKey
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptKeys
     */
    private static function keys(string $appKey): AttemptKeys
    {
        return new AttemptKeys(new Repository(['app' => ['key' => $appKey]]));
    }
}
