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
use Tests\Fixtures\Identities\TestUser;

/**
 * A queued job that sets its own identity when it names one, and only then,
 * optionally renames a factor or sends it a code, and notes what the package
 * answered, whether anything was written, or fails when told to.
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
     * Constructor.
     *
     * @param  string  $name
     * @param  ?int  $person
     * @param  ?string  $renames
     * @param  ?string  $sendsTo
     * @param  bool  $fails
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
    ) {}

    /**
     * Run the job.
     *
     * @param  \Tests\Integration\Process\Fixtures\JobObservations  $observations
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     *
     * @throws \RuntimeException
     */
    public function handle(JobObservations $observations, Dispatcher $events): void
    {
        $before = $this->stored();

        if ($this->person !== null) {

            $user = TestUser::query()->findOrFail($this->person);

            Auth::guard('web')->setUser($user);

            $events->dispatch(new Login('web', $user, false));
        }

        if ($this->fails) {
            throw new \RuntimeException('The job failed.');
        }

        if ($this->renames !== null) {
            Mfa::renameFactor($this->renames, 'Renamed by ' . $this->name);
        }

        if ($this->sendsTo !== null) {
            Mfa::sendCode($this->sendsTo);
        }

        $observations->seen[] = [
            'job'      => $this->name,
            'identity' => Auth::guard('web')->id(),
            'factors'  => array_map(static fn (FactorSummary $factor): string => $factor->id, Mfa::factors()),
            'proofs'   => count(Mfa::proofs()),
            'changed'  => $before !== $this->stored(),
        ];
    }

    /**
     * What the package's tables the job could write hold, in a form that can be
     * compared.
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
