<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Issues and checks delivered codes, one row per challenge, on the write
 * connection. Every change is a single conditional statement, so concurrent
 * checks never exceed `max_attempts` and only one correct submission wins.
 * Issuing reads then writes, so the caller must serialise per identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeliveredCodes
{
    /** @var \SineMacula\Laravel\Mfa\Codes\CodeSettings */
    private CodeSettings $settings;

    /** @var \SineMacula\Laravel\Mfa\Codes\CodeKeys */
    private CodeKeys $keys;

    /** @var \SineMacula\Laravel\Mfa\Codes\SendWaits */
    private SendWaits $waits;

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  (\Closure(int): string)|null  $generator
     */
    public function __construct(

        // Read on every call.
        Repository $config,

        /** Replaces `random_int()` so tests can know the code. */
        private ?\Closure $generator = null,
    ) {
        $this->settings = new CodeSettings($config);
        $this->keys     = new CodeKeys($config);
        $this->waits    = new SendWaits($this->settings);
    }

    /**
     * Start a challenge or resend the open one; an int is the seconds to wait.
     *
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?string  $destination
     * @return int|\SineMacula\Laravel\Mfa\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \JsonException
     *
     * @phpstan-impure
     */
    public function issue(string $factorId, ProofBinding $binding, CarbonImmutable $now, #[\SensitiveParameter] ?string $destination = null): int|IssuedCode
    {
        $session = $this->keys->session($binding->sessionId);
        $target  = $this->keys->destination($binding, $factorId, $destination);
        $open    = $this->open($factorId, $binding, $session, $now);
        $wait    = max(
            $this->waits->caps($target, $binding, $now),
            $open === null ? $this->waits->restart($target, $binding, $now) : $this->resendWait($open, $now),
        );

        if ($wait > 0) {
            return $wait;
        }

        return $open === null
            ? $this->start($factorId, $binding, $session, $target, $now)
            : $this->resend($open, $factorId, $binding, $now);
    }

    /**
     * Consume the challenge's code when it matches. A used challenge answers
     * `replayed` for its last code and `spent` for any other.
     *
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $now
     * @param  string  $challengeId
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    public function check(string $factorId, ProofBinding $binding, #[\SensitiveParameter] string $code, CarbonImmutable $now, string $challengeId): CodeCheck
    {
        $row = self::firstOf($this->bound($factorId, $binding, $this->keys->session($binding->sessionId))->where('id', $challengeId));

        if ($row === null) {
            return CodeCheck::MISSING;
        }

        if ($row->consumed_at !== null) {
            return $this->matches($row, $factorId, $binding, $code) ? CodeCheck::REPLAYED : CodeCheck::SPENT;
        }

        return $this->attempt($row, $factorId, $binding, $code, $now);
    }

    /**
     * Count the attempt before comparing; a check that cannot count never
     * compares and answers from a fresh read.
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
     * Seconds until a resend; an exhausted challenge waits until it ends. Zero
     * or less means now.
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
     * @param  string  $factorId
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $session
     * @param  string  $target
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Mfa\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \JsonException
     */
    private function start(string $factorId, ProofBinding $binding, string $session, string $target, CarbonImmutable $now): IssuedCode
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
            'destination_hash'     => $target,
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
     * Replace the code, keeping the attempt count. Digits are redrawn until
     * they differ from the last code's, which would otherwise still match.
     * Returns 1 second when a concurrent change got there first.
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
     * Answer for a check that could not count its attempt.
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
     * @return \Illuminate\Database\Query\Builder
     */
    private function table(): QueryBuilder
    {
        $model = new Code;

        return $model->getConnection()->table($model->getTable());
    }

    /**
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Mfa\Models\Code>  $query
     * @return ?\SineMacula\Laravel\Mfa\Models\Code
     */
    private static function firstOf(Builder $query): ?Code
    {
        $row = $query->orderByDesc('created_at')->orderByDesc('id')->first();

        return $row instanceof Code ? $row : null;
    }

    /**
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
}
