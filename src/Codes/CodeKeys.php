<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * The keyed digests behind delivered codes: the hash of a code, bound to its
 * challenge, its issue, its factor and the whole binding (identity,
 * application, session and purpose), the digest a challenge's session is stored
 * under, and the digest of what a code was sent to. Each is an HMAC-SHA256 with
 * its own key derived from the application key (`app.key`).
 *
 * A code has a few million values at most, so a plain hash of it could be
 * reversed by anyone who reads the table, from a backup or a replica, say, by
 * hashing every candidate; a keyed hash cannot be recomputed without the key.
 * The session digest keeps the session's id, a bearer secret, out of the table
 * the same way, and the destination digest a phone number or an email address.
 * Rotating the application key only invalidates the codes outstanding, and
 * starts the send caps afresh.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeKeys
{
    /** @var string What the code key is derived for, so it is used for nothing else. */
    private const string CODE_PURPOSE = 'sinemacula/laravel-mfa delivered code hashes';

    /** @var string What the session key is derived for, so it is used for nothing else. */
    private const string SESSION_PURPOSE = 'sinemacula/laravel-mfa delivered code sessions';

    /** @var string What the destination key is derived for, so it is used for nothing else. */
    private const string DESTINATION_PURPOSE = 'sinemacula/laravel-mfa delivered code destinations';

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
     * The hash of a code sent as the given issue of the challenge, for the
     * factor and the binding, as 64 hexadecimal characters. The same code
     * hashes differently for any other challenge, issue, factor, identity,
     * application, session or purpose.
     *
     * @param  string  $challengeId
     * @param  int  $issue
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $code
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function code(string $challengeId, int $issue, string $factorId, ProofBinding $binding, #[\SensitiveParameter] string $code): string
    {
        $parts = [
            'code',
            $challengeId,
            $issue,
            $factorId,
            $binding->identityType,
            $binding->identityKey,
            $binding->application,
            $binding->sessionId,
            $binding->purpose->value,
            $code,
        ];

        return hash_hmac('sha256', implode("\0", $parts), $this->derive(self::CODE_PURPOSE));
    }

    /**
     * The digest a challenge's session is stored and looked up under, as 64
     * hexadecimal characters.
     *
     * @param  string  $sessionId
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function session(#[\SensitiveParameter] string $sessionId): string
    {
        return hash_hmac('sha256', $sessionId, $this->derive(self::SESSION_PURPOSE));
    }

    /**
     * The digest of what the owner's codes are sent to, as 64 hexadecimal
     * characters, which the send caps count by: the factor's destination, or
     * the factor itself when it holds none. It outlives the factor, so a
     * pending factor discarded for a new one to the same destination leaves its
     * sends counted.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $factorId
     * @param  ?string  $destination
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function destination(ProofBinding $binding, string $factorId, #[\SensitiveParameter] ?string $destination): string
    {
        $parts = [
            $binding->identityType,
            $binding->identityKey,
            $destination === null ? 'factor' : 'destination',
            $destination ?? $factorId,
        ];

        return hash_hmac('sha256', implode("\0", $parts), $this->derive(self::DESTINATION_PURPOSE));
    }

    /**
     * Read the application key, failing closed when it is not set; the package
     * checks it when an application enables a type that delivers codes.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->applicationKey();
    }

    /**
     * The key derived from the application key for the purpose.
     *
     * @param  string  $purpose
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function derive(string $purpose): string
    {
        return hash_hmac('sha256', $purpose, $this->applicationKey(), true);
    }

    /**
     * The application key, which must be set.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function applicationKey(): string
    {
        $key = $this->config->get('app.key');

        if (!is_string($key) || $key === '') {
            throw new \InvalidArgumentException('Delivered codes are hashed with a key derived from the application key; set app.key.');
        }

        return $key;
    }
}
