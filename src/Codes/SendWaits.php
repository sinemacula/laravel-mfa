<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Collection;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Waits imposed by the send caps and enrolment restart cooldown, read from the
 * write connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SendWaits
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeSettings  $settings
     */
    public function __construct(

        /** Code settings. */
        private CodeSettings $settings,
    ) {}

    /**
     * Seconds until both the destination and identity caps allow a send, across
     * sessions; zero or less means now.
     *
     * @param  string  $target
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function caps(string $target, ProofBinding $binding, CarbonImmutable $now): int
    {
        $window = $this->settings->sendWindowMinutes() * 60;
        $since  = (new Code)->fromDateTime($now->subSeconds($window));

        $destination = WriteConnection::query(Code::query())
            ->where('destination_hash', $target)
            ->where('sent_at', '>', $since)
            ->get();

        $identity = WriteConnection::query(Code::query())
            ->where('authenticatable_type', $binding->identityType)
            ->where('authenticatable_id', $binding->identityKey)
            ->where('sent_at', '>', $since)
            ->get();

        return max(
            self::window($destination, $this->settings->factorSendLimit(), $window, $now),
            self::window($identity, $this->settings->identitySendLimit(), $window, $now),
        );
    }

    /**
     * Seconds until a restarted enrolment may send to the destination again;
     * zero or less means now. Other purposes never wait.
     *
     * @param  string  $target
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function restart(string $target, ProofBinding $binding, CarbonImmutable $now): int
    {
        if ($binding->purpose !== Purpose::ENROLLMENT) {
            return 0;
        }

        $last = WriteConnection::query(Code::query())
            ->where('destination_hash', $target)
            ->where('purpose', Purpose::ENROLLMENT->value)
            ->orderByDesc('sent_at')
            ->first();

        return $last === null ? 0 : $last->sent_at->getTimestamp() + $this->settings->resendCooldownSeconds() - $now->getTimestamp();
    }

    /**
     * Seconds until the sends in the window drop below the limit; zero or less
     * means now.
     *
     * @param  \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Mfa\Models\Code>  $rows
     * @param  int  $limit
     * @param  int  $window
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     */
    private static function window(Collection $rows, int $limit, int $window, CarbonImmutable $now): int
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
