<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Database\IdentityStateRow;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * An identity's recent sends, kept on its state row and read `FOR UPDATE`: a
 * plain read on MySQL may come from an older snapshot and miss a send committed
 * meanwhile. The caller must hold the identity's state lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SendLedger
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeSettings  $settings
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  list<array{at: int, to: string, enrollment: bool}>  $sends
     */
    private function __construct(

        /** Code settings. */
        private CodeSettings $settings,

        /** Whose state row holds the sends. */
        private ProofOwner $owner,

        /** Each send's Unix time and destination digest. */
        private array $sends,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeSettings  $settings
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return self
     *
     * @throws \Illuminate\Database\RecordsNotFoundException
     * @throws \Illuminate\Database\MultipleRecordsFoundException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public static function read(CodeSettings $settings, ProofBinding $binding): self
    {
        $owner = ProofOwner::boundBy($binding);
        $row   = (array) IdentityStateRow::of($owner)->lockForUpdate()->sole(['code_sends']);

        /** @var list<array{at: int, to: string, enrollment: bool}> $sends */
        $sends = is_string($row['code_sends']) ? json_decode($row['code_sends'], true, flags: JSON_THROW_ON_ERROR) : [];

        return new self($settings, $owner, $sends);
    }

    /**
     * Seconds until both the destination and identity caps allow a send, across
     * sessions; zero or less means now.
     *
     * @param  string  $target
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function caps(string $target, CarbonImmutable $now): int
    {
        $window  = $this->settings->sendWindowMinutes() * 60;
        $counted = array_filter($this->sends, static fn (array $send): bool => $send['at'] > $now->getTimestamp() - $window);
        $sentTo  = array_filter($counted, static fn (array $send): bool => $send['to'] === $target);

        return max(
            self::window(array_column($sentTo, 'at'), $this->settings->factorSendLimit(), $window, $now),
            self::window(array_column($counted, 'at'), $this->settings->identitySendLimit(), $window, $now),
        );
    }

    /**
     * Seconds until a restarted enrolment may send to the destination again;
     * zero or less means now. Other purposes never wait.
     *
     * @param  string  $target
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function restart(string $target, Purpose $purpose, CarbonImmutable $now): int
    {
        if ($purpose !== Purpose::ENROLLMENT) {
            return 0;
        }

        $times = array_column(array_filter($this->sends, static fn (array $send): bool => $send['enrollment'] && $send['to'] === $target), 'at');

        return $times === [] ? 0 : max($times) + $this->settings->resendCooldownSeconds() - $now->getTimestamp();
    }

    /**
     * Add a send, dropping those neither the caps nor the cooldown still count.
     *
     * @param  string  $target
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function record(string $target, Purpose $purpose, CarbonImmutable $now): void
    {
        $kept  = max($this->settings->sendWindowMinutes() * 60, $this->settings->resendCooldownSeconds());
        $sends = array_filter($this->sends, static fn (array $send): bool => $send['at'] > $now->getTimestamp() - $kept);

        $sends[] = ['at' => $now->getTimestamp(), 'to' => $target, 'enrollment' => $purpose === Purpose::ENROLLMENT];

        IdentityStateRow::of($this->owner)->update(['code_sends' => json_encode(array_values($sends), JSON_THROW_ON_ERROR)]);
    }

    /**
     * Seconds until the sends in the window drop below the limit; zero or less
     * means now.
     *
     * @param  list<int>  $times
     * @param  int  $limit
     * @param  int  $window
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     */
    private static function window(array $times, int $limit, int $window, CarbonImmutable $now): int
    {
        if (count($times) < $limit) {
            return 0;
        }

        sort($times);

        return $times[count($times) - $limit] + $window - $now->getTimestamp();
    }
}
