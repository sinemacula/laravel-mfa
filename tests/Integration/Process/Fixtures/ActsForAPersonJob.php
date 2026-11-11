<?php

declare(strict_types = 1);

namespace Tests\Integration\Process\Fixtures;

use Illuminate\Auth\Events\Login;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;

/**
 * A queued job that may act for a person and notes what the package answered
 * and whether anything was written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ActsForAPersonJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * @param  string  $name
     * @param  ?int  $person
     * @param  ?string  $renames
     * @param  ?string  $sendsTo
     * @param  bool  $fails
     * @param  ?string  $verifies
     * @param  ?string  $code
     * @param  bool  $signsIn
     */
    public function __construct(

        /** What the test calls the job. */
        public string $name,

        /** The person the job acts for, if any. */
        public ?int $person = null,

        /** The factor the job renames, if any. */
        public ?string $renames = null,

        /** The factor the job sends a code to, if any. */
        public ?string $sendsTo = null,

        /** Whether the job fails once it has set its identity. */
        public bool $fails = false,

        /** The factor the job verifies, if any. */
        public ?string $verifies = null,

        /** The code it verifies that factor with. */
        public ?string $code = null,

        /** Whether setting its identity fires `Login`, beginning a sign-in. */
        public bool $signsIn = true,
    ) {}

    /**
     * @param  \Tests\Integration\Process\Fixtures\JobObservations  $observations
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     *
     * @throws \RuntimeException
     */
    public function handle(JobObservations $observations, Dispatcher $events): void
    {
        $before = $this->stored();

        $this->identify($events);

        if ($this->fails) {
            throw new \RuntimeException('The job failed.');
        }

        $this->act();

        $observations->seen[] = [
            'job'      => $this->name,
            'identity' => Auth::guard('web')->id(),
            'factors'  => array_map(static fn (FactorSummary $factor): string => $factor->id, Mfa::factors(Callers::current())),
            'proofs'   => count(Mfa::proofs(Callers::current())),
            'changed'  => $before !== $this->stored(),
        ];
    }

    /**
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     */
    private function identify(Dispatcher $events): void
    {
        if ($this->person === null) {
            return;
        }

        $user = TestUser::query()->findOrFail($this->person);

        Auth::guard('web')->setUser($user);

        if (!$this->signsIn) {
            return;
        }

        $events->dispatch(new Login('web', $user, false));
    }

    /**
     * @return void
     */
    private function act(): void
    {
        if ($this->renames !== null) {
            Mfa::renameFactor(Callers::current(), $this->renames, 'Renamed by ' . $this->name);
        }

        if ($this->sendsTo !== null) {
            Mfa::sendCode(Callers::current(), $this->sendsTo);
        }

        if ($this->verifies === null) {
            return;
        }

        Mfa::verify(Callers::current(), Submission::factor($this->verifies, (string) $this->code));
    }

    /**
     * Snapshot of the tables the job could write.
     *
     * @return string
     *
     * @throws \JsonException
     */
    private function stored(): string
    {
        $connection = DB::connection(StorageConnection::name());

        return json_encode([
            $connection->table(TableNames::of(TableNames::FACTORS))->orderBy('id')->get()->all(),
            $connection->table(TableNames::of(TableNames::IDENTITY_STATES))->orderBy('id')->get()->all(),
        ], JSON_THROW_ON_ERROR);
    }
}
