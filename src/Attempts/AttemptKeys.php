<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * Attempt row keys: HMAC-SHA256 keyed from `app.key`, because identity keys and
 * IP addresses are easy to enumerate and a plain hash would be reversible.
 * Rotating `app.key` resets the throttles but not the stored lockouts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttemptKeys
{
    /** @var string Derivation label for throttle keys. */
    private const string PURPOSE = 'sinemacula/laravel-mfa attempt throttles';

    /** @var list<string> IPv4-mapped (`::ffff:0:0/96`) and NAT64 (`64:ff9b::/96`) prefixes. */
    private const array IPV4_CARRYING_PREFIXES = ["\0\0\0\0\0\0\0\0\0\0\xff\xff", "\0\x64\xff\x9b\0\0\0\0\0\0\0\0"];

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call so a changed `app.key` applies. */
        private Repository $config,
    ) {}

    /**
     * @param  string  $type
     * @param  string  $key
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function identity(string $type, string $key): string
    {
        return $this->digest(AttemptScope::IDENTITY, [$type, $key]);
    }

    /**
     * @param  string  $ip
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function ip(string $ip): string
    {
        return $this->digest(AttemptScope::IP, [self::canonicalIp($ip)]);
    }

    /**
     * IPv4, or the IPv4 an IPv6 address carries; other IPv6 collapses to its
     * /64, since one client usually holds a whole /64.
     *
     * @param  string  $ip
     * @return string
     */
    public static function canonicalIp(string $ip): string
    {
        $packed = inet_pton($ip);

        if ($packed === false) {
            return $ip;
        }

        if (in_array(substr($packed, 0, 12), self::IPV4_CARRYING_PREFIXES, true)) {
            $packed = substr($packed, 12);
        }

        return strlen($packed) === 4
            ? (string) inet_ntop($packed)
            : inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8)) . '/64';
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @param  list<string>  $parts
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function digest(AttemptScope $scope, array $parts): string
    {
        return hash_hmac('sha256', implode("\0", [$scope->value, ...$parts]), $this->secret());
    }

    /**
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function secret(): string
    {
        $key = $this->config->get('app.key');

        if (!is_string($key) || $key === '') {
            throw new \InvalidArgumentException('The attempt throttles key their rows with the application key; set `app.key`.');
        }

        return hash_hmac('sha256', self::PURPOSE, $key, true);
    }
}
