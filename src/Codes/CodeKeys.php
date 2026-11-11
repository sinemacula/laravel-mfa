<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * HMAC-SHA256 digests of delivered codes, sessions and destinations, keyed from
 * `app.key` because a code's few million values make a plain hash reversible.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeKeys
{
    /** @var string Derivation label for code hashes. */
    private const string CODE_PURPOSE = 'sinemacula/laravel-mfa delivered code hashes';

    /** @var string Derivation label for session digests. */
    private const string SESSION_PURPOSE = 'sinemacula/laravel-mfa delivered code sessions';

    /** @var string Derivation label for destination digests. */
    private const string DESTINATION_PURPOSE = 'sinemacula/laravel-mfa delivered code destinations';

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call so a changed `app.key` applies. */
        private Repository $config,
    ) {}

    /**
     * Hash of a code, bound to its challenge, issue, factor and binding.
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
     * Digest a challenge's session id is stored and looked up under.
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
     * Digest the send caps count by: the destination, or the factor when it
     * holds none, so replacing a factor keeps its sends counted.
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
     * Fail when `app.key` is not set.
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
