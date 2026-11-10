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
 * The waits the caps on sends impose before a code may be issued, read from the
 * codes table's write PDO: the caps on codes sent to a destination and to an
 * identity within the send window, and the cooldown a restarted enrolment waits
 * out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SendWaits
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeSettings  $settings
     */
    public function __construct(

        /** The code settings the caps and the cooldown are read from. */
        private CodeSettings $settings,
    ) {}

    /**
     * The seconds until the factor's destination and the identity are both
     * under their caps on codes sent within the send window, across every
     * session; zero or less when they are now.
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
     * The seconds until a new enrolment challenge may send to the destination:
     * until the cooldown since the last enrolment code to it has passed, whose
     * factor a restart has discarded. Zero or less means now, as it is for any
     * other purpose, whose new challenge has no code before it to wait out.
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
