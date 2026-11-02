<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * The delivered code engine: issues the codes of a challenge and checks codes
 * against it, on the codes table's connection and always on its write PDO.
 *
 * A challenge is one row, bound to a factor and to a binding (the identity, the
 * application, the session and the purpose), and holds one live code at a time.
 * A code is `length` digits drawn uniformly with `random_int()`, stored only as
 * a keyed hash of the code, its challenge, its issue, its factor and its
 * binding (see `CodeKeys`), so it matches nothing else; the session is stored
 * as a keyed digest too. Issuing for a binding with an open challenge (a code
 * not yet used, sent less than `challenge_ttl_minutes` ago) is a resend: a new
 * code replaces the previous one, which stops working at once, the attempt
 * count is kept, and the new code expires at the code lifetime or the end of
 * the challenge, whichever is sooner; its digits are never the previous code's.
 * A resend waits out the cooldown since the last code, and a challenge that has
 * used up its attempts sends no more until it ends. Every issue is refused
 * while the factor or the identity has been sent its cap of codes within the
 * send window, across every session; each send is counted for the window from
 * its own time, which the challenge records.
 *
 * A check counts an attempt against the issue it read before it compares
 * anything, so concurrent checks never exceed `max_attempts`, and uses the code
 * up only with a second conditional statement, so of two correct submissions
 * exactly one is accepted. Every change is one statement the database applies
 * atomically, and a database error propagates. Issuing reads the counts it caps
 * on and then writes, so its caller serialises the issues of one identity (see
 * `CodeService`).
 *
 * The engine keeps no state between calls: the settings and the key are read
 * from the configuration each time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeliveredCodes
{
    /** @var \SineMacula\Laravel\Mfa\Codes\CodeSettings The code settings. */
    private CodeSettings $settings;

    /** @var \SineMacula\Laravel\Mfa\Codes\CodeKeys The keyed digests of codes and sessions. */
    private CodeKeys $keys;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  (\Closure(int): string)|null  $generator
     */
    public function __construct(

        // Configuration the settings and the key are read from on every call.
        Repository $config,

        /** Draws a code of the given number of digits instead of `random_int()`; for tests that need a known code. */
        private ?\Closure $generator = null,
    ) {
        $this->settings = new CodeSettings($config);
        $this->keys     = new CodeKeys($config);
    }

    /**
     * Issue a code for the factor's challenge under the binding: a new
     * challenge, or a resend of the open one. Returns the code issued, or the
     * seconds, at least 1, until another may be.
     *
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return int|\SineMacula\Laravel\Mfa\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \JsonException
     *
     * @phpstan-impure
     */
    public function issue(string $factorId, ProofBinding $binding, CarbonImmutable $now): int|IssuedCode
    {
        $session = $this->keys->session($binding->sessionId);
        $open    = $this->open($factorId, $binding, $session, $now);
        $wait    = $this->capWait($factorId, $binding, $now);

        if ($open !== null) {
            $wait = max($wait, $this->resendWait($open, $now));
        }

        if ($wait > 0) {
            return $wait;
        }

        return $open === null
            ? $this->start($factorId, $binding, $session, $now)
            : $this->resend($open, $factorId, $binding, $now);
    }

    /**
     * Check the code against the factor's challenge under the binding (the one
     * named, or the latest), and use it up when it matches.
     *
     * A binding with no challenge, or a challenge named that is not the
     * binding's, is `missing`; a used challenge is `replayed` for its last code
     * and `spent` for any other; an expired code or a challenge that has used
     * up its attempts says so, without counting. A check that can count an
     * attempt against the issue it read compares the code, and accepts it only
     * when it also uses that issue up; one that cannot (a concurrent resend,
     * check or expiry got there first) never compares, and answers from a fresh
     * read.
     *
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?string  $challengeId
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    public function check(string $factorId, ProofBinding $binding, #[\SensitiveParameter] string $code, CarbonImmutable $now, ?string $challengeId = null): CodeCheck
    {
        $query = $this->bound($factorId, $binding, $this->keys->session($binding->sessionId));
        $row   = self::firstOf($challengeId === null ? $query : $query->where('id', $challengeId));

        if ($row === null) {
            return CodeCheck::MISSING;
        }

        if ($row->consumed_at !== null) {
            return $this->matches($row, $factorId, $binding, $code) ? CodeCheck::REPLAYED : CodeCheck::SPENT;
        }

        return $this->attempt($row, $factorId, $binding, $code, $now);
    }

    /**
     * Check the code against the challenge's live issue: count the attempt,
     * then compare, accepting the code only when this check also uses the issue
     * up. An issue that has expired or used up its attempts counts nothing, and
     * the fresh read that follows says which.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Code  $row
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    private function attempt(Code $row, string $factorId, ProofBinding $binding, #[\SensitiveParameter] string $code, CarbonImmutable $now): CodeCheck
    {
        $max = $this->settings->maxAttempts();

        if (!$this->countAttempt($row, $max, $now)) {
            return $this->recheck($row, $max, $now);
        }

        return $this->matches($row, $factorId, $binding, $code) && $this->useUp($row, $now)
            ? CodeCheck::ACCEPTED
            : CodeCheck::INVALID;
    }

    /**
     * The binding's open challenge: not used, and started less than the
     * challenge lifetime ago.
     *
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Mfa\Models\Code
     *
     * @throws \InvalidArgumentException
     */
    private function open(string $factorId, ProofBinding $binding, string $session, CarbonImmutable $now): ?Code
    {
        $started = (new Code)->fromDateTime($now->subMinutes($this->settings->challengeTtlMinutes()));

        return self::firstOf($this->bound($factorId, $binding, $session)->whereNull('consumed_at')->where('created_at', '>', $started));
    }

    /**
     * The seconds until the open challenge may be sent another code: until it
     * ends once it has used up its attempts, otherwise until the cooldown since
     * its last code has passed. Zero or less means now.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Code  $open
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function resendWait(Code $open, CarbonImmutable $now): int
    {
        if ($open->attempts >= $this->settings->maxAttempts()) {
            return $this->deadline($open)->getTimestamp() - $now->getTimestamp();
        }

        return $open->sent_at->getTimestamp() + $this->settings->resendCooldownSeconds() - $now->getTimestamp();
    }

    /**
     * The seconds until the factor and the identity are both under their caps
     * on codes sent within the send window, across every session; zero or less
     * when they are now.
     *
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function capWait(string $factorId, ProofBinding $binding, CarbonImmutable $now): int
    {
        $window = $this->settings->sendWindowMinutes() * 60;
        $since  = (new Code)->fromDateTime($now->subSeconds($window));

        $factor = WriteConnection::query(Code::query())
            ->where('factor_id', $factorId)
            ->where('sent_at', '>', $since)
            ->get();

        $identity = WriteConnection::query(Code::query())
            ->where('authenticatable_type', $binding->identityType)
            ->where('authenticatable_id', $binding->identityKey)
            ->where('sent_at', '>', $since)
            ->get();

        return max(
            self::windowWait($factor, $this->settings->factorSendLimit(), $window, $now),
            self::windowWait($identity, $this->settings->identitySendLimit(), $window, $now),
        );
    }

    /**
     * Start a new challenge for the binding with its first code.
     *
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Mfa\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \JsonException
     */
    private function start(string $factorId, ProofBinding $binding, string $session, CarbonImmutable $now): IssuedCode
    {
        $model   = new Code;
        $id      = Str::lower((string) Str::ulid());
        $code    = $this->draw();
        $expires = $now->addMinutes($this->settings->ttlMinutes());
        $at      = $model->fromDateTime($now);

        $this->table()->insert([
            'id'                   => $id,
            'factor_id'            => $factorId,
            'authenticatable_type' => $binding->identityType,
            'authenticatable_id'   => $binding->identityKey,
            'purpose'              => $binding->purpose->value,
            'application'          => $binding->application,
            'session_id'           => $session,
            'code_hash'            => $this->keys->code($id, 1, $factorId, $binding, $code),
            'attempts'             => 0,
            'sends'                => 1,
            'sent_at'              => $at,
            'sent_times'           => json_encode([$now->getTimestamp()], JSON_THROW_ON_ERROR),
            'expires_at'           => $model->fromDateTime($expires),
            'consumed_at'          => null,
            'created_at'           => $at,
            'updated_at'           => $at,
        ]);

        return new IssuedCode($id, $code, $expires);
    }

    /**
     * Send the open challenge a new code, which replaces its last, keeping its
     * attempts and never working past the end of the challenge. The new code is
     * drawn again until its digits differ from the last code's, which would
     * otherwise still match under the new issue. Returns the code, or 1 second
     * when a concurrent change got to the challenge first.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Code  $open
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return int|\SineMacula\Laravel\Mfa\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \JsonException
     */
    private function resend(Code $open, string $factorId, ProofBinding $binding, CarbonImmutable $now): int|IssuedCode
    {
        $issue = $open->sends + 1;

        do {
            $code = $this->draw();
        } while ($this->matches($open, $factorId, $binding, $code));

        $lifetime = $now->addMinutes($this->settings->ttlMinutes());
        $deadline = $this->deadline($open);
        $expires  = $lifetime->greaterThan($deadline) ? $deadline : $lifetime;
        $at       = $open->fromDateTime($now);

        $updated = $this->table()
            ->where('id', $open->id)
            ->where('sends', $open->sends)
            ->whereNull('consumed_at')
            ->update([
                'code_hash'  => $this->keys->code($open->id, $issue, $factorId, $binding, $code),
                'sends'      => $issue,
                'sent_at'    => $at,
                'sent_times' => json_encode([...$open->sent_times, $now->getTimestamp()], JSON_THROW_ON_ERROR),
                'expires_at' => $open->fromDateTime($expires),
                'updated_at' => $at,
            ]);

        return $updated === 1 ? new IssuedCode($open->id, $code, $expires) : 1;
    }

    /**
     * When the challenge ends: the challenge lifetime after its first code.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Code  $row
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private function deadline(Code $row): CarbonImmutable
    {
        return CarbonImmutable::instance($row->created_at)->addMinutes($this->settings->challengeTtlMinutes());
    }

    /**
     * The answer for a check that could not count its attempt against the issue
     * it read: why that issue refuses checks when it is still the challenge's
     * code and does; otherwise `invalid`.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Code  $row
     * @param  int  $max
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    private function recheck(Code $row, int $max, CarbonImmutable $now): CodeCheck
    {
        $fresh = WriteConnection::query(Code::query())->find($row->id);

        if (!$fresh instanceof Code || $fresh->sends !== $row->sends) {
            return CodeCheck::INVALID;
        }

        return self::refusal($fresh, $max, $now) ?? CodeCheck::INVALID;
    }

    /**
     * Whether the code is the one last issued for the challenge, compared in
     * constant time.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Code  $row
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $code
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function matches(Code $row, string $factorId, ProofBinding $binding, #[\SensitiveParameter] string $code): bool
    {
        return hash_equals($row->code_hash, $this->keys->code($row->id, $row->sends, $factorId, $binding, $code));
    }

    /**
     * Count one attempt against the issue, in one statement, while it is still
     * the challenge's code, unused, unexpired and under its maximum. Returns
     * whether it did.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Code  $row
     * @param  int  $max
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     *
     * @imperative
     */
    private function countAttempt(Code $row, int $max, CarbonImmutable $now): bool
    {
        return $this->table()
            ->where('id', $row->id)
            ->where('sends', $row->sends)
            ->whereNull('consumed_at')
            ->where('expires_at', '>', $row->fromDateTime($now))
            ->where('attempts', '<', $max)
            ->increment('attempts') === 1;
    }

    /**
     * Use the issue up, in one statement, while it is still the challenge's
     * code and unused. Returns whether this call used it.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Code  $row
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @phpstan-impure
     *
     * @imperative
     */
    private function useUp(Code $row, CarbonImmutable $now): bool
    {
        $at = $row->fromDateTime($now);

        return $this->table()
            ->where('id', $row->id)
            ->where('sends', $row->sends)
            ->whereNull('consumed_at')
            ->update(['consumed_at' => $at, 'updated_at' => $at]) === 1;
    }

    /**
     * The factor's challenges under the binding, read from the write PDO.
     *
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $session
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Mfa\Models\Code>
     */
    private function bound(string $factorId, ProofBinding $binding, string $session): Builder
    {
        return WriteConnection::query(Code::query())
            ->where('factor_id', $factorId)
            ->where('authenticatable_type', $binding->identityType)
            ->where('authenticatable_id', $binding->identityKey)
            ->where('purpose', $binding->purpose->value)
            ->where('application', $binding->application)
            ->where('session_id', $session);
    }

    /**
     * Draw a code of the configured number of digits, each drawn uniformly.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    private function draw(): string
    {
        $length = $this->settings->length();

        if ($this->generator !== null) {
            return ($this->generator)($length);
        }

        $code = '';

        for ($digit = 0; $digit < $length; $digit++) {
            $code .= random_int(0, 9);
        }

        return $code;
    }

    /**
     * A query on the codes' table, on its own connection, for the writes.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function table(): QueryBuilder
    {
        $model = new Code;

        return $model->getConnection()->table($model->getTable());
    }

    /**
     * The newest challenge the query finds, or `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Mfa\Models\Code>  $query
     * @return ?\SineMacula\Laravel\Mfa\Models\Code
     */
    private static function firstOf(Builder $query): ?Code
    {
        $row = $query->orderByDesc('created_at')->orderByDesc('id')->first();

        return $row instanceof Code ? $row : null;
    }

    /**
     * Why the challenge refuses checks: used (`spent`), expired, or out of
     * attempts; `null` when it takes one.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Code  $row
     * @param  int  $max
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    private static function refusal(Code $row, int $max, CarbonImmutable $now): ?CodeCheck
    {
        return match (true) {
            $row->consumed_at !== null                               => CodeCheck::SPENT,
            $row->expires_at->getTimestamp() <= $now->getTimestamp() => CodeCheck::EXPIRED,
            $row->attempts >= $max                                   => CodeCheck::EXHAUSTED,
            default                                                  => null,
        };
    }

    /**
     * The seconds until fewer than the limit of the rows' sends are within the
     * window: until the send that must leave it for one more to fit has left, a
     * window after it was made. Each send leaves the window on its own, and one
     * already outside it gives no wait. Zero or less means now.
     *
     * @param  \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Mfa\Models\Code>  $rows
     * @param  int  $limit
     * @param  int  $window
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     */
    private static function windowWait(Collection $rows, int $limit, int $window, CarbonImmutable $now): int
    {
        $times = [];

        foreach ($rows as $row) {
            array_push($times, ...$row->sent_times);
        }

        if (count($times) < $limit) {
            return 0;
        }

        sort($times);

        return $times[count($times) - $limit] + $window - $now->getTimestamp();
    }
}
