<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * The keys the attempts table stores its rows under: HMAC-SHA256 digests of the
 * scope and the subject it counts, keyed with a key derived from the
 * application key (`app.key`).
 *
 * What a row counts (a factor id, an identity's key, an IP address) is usually
 * easy to enumerate, so a plain digest of it could be reversed by anyone who
 * reads the table, from a backup or a replica, by hashing every candidate. A
 * keyed digest cannot be recomputed without the application key, and stays
 * deterministic, so every server counts in the same row. Rotating the
 * application key starts every throttle afresh; the durable counts on the
 * factor and identity state rows are kept.
 *
 * An IP address is counted by the client it stands for: an IPv4 address, or the
 * IPv4 address an IPv6 address carries (IPv4-mapped, or translated through the
 * NAT64 well-known prefix), in dotted decimal; any other IPv6 address as the
 * /64 network it belongs to, since a single client is usually given a whole /64
 * and could otherwise count each of its addresses separately.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttemptKeys
{
    /** @var string What the key derived from the application key is for, so it is used for nothing else. */
    private const string PURPOSE = 'sinemacula/laravel-mfa attempt throttles';

    /** @var list<string> The first twelve bytes of the IPv6 prefixes whose last four carry an IPv4 client's address: IPv4-mapped (`::ffff:0:0/96`) and the NAT64 well-known prefix (`64:ff9b::/96`). */
    private const array IPV4_CARRYING_PREFIXES = ["\0\0\0\0\0\0\0\0\0\0\xff\xff", "\0\x64\xff\x9b\0\0\0\0\0\0\0\0"];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the application key is read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The key of a factor's row: the lockout its failures in a row applied.
     *
     * @param  string  $factor
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function factor(string $factor): string
    {
        return $this->digest(AttemptScope::FACTOR, [$factor]);
    }

    /**
     * The key of an identity's row: its failures within the window.
     *
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
     * The key of an IP address's row: its failures within the window, counted
     * by the client the address stands for.
     *
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
     * The canonical form of an IP address: an IPv4 address, or the IPv4 address
     * an IPv6 address carries, in dotted decimal; any other IPv6 address as its
     * /64 network. Anything that is not an IP address is counted as given.
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
     * The keyed digest of the scope and the parts, as 64 hexadecimal
     * characters.
     *
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
     * The key the digests are made with, derived from the application key.
     *
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
