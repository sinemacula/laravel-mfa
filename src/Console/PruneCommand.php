<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Mfa\Lifecycle\RecordPruner;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `mfa:prune`: deletes the records `Lifecycle\RecordPruner` deletes and prints
 * how many of each kind went. It prints no secret and schedules nothing;
 * schedule this or the pruner itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: self::NAME)]
final class PruneCommand extends Command
{
    /** @var string The command's name. */
    public const string NAME = 'mfa:prune';

    /** @var string The name and signature of the console command. */
    protected $signature = self::NAME;

    /** @var string The console command description. */
    protected $description = 'Delete abandoned enrolments, expired codes, used or replaced recovery codes and ended throttle windows';

    /**
     * Prune, and report how many records of each kind went.
     *
     * @param  \SineMacula\Laravel\Mfa\Lifecycle\RecordPruner  $pruner
     * @return int
     *
     * @throws \Throwable
     */
    public function handle(RecordPruner $pruner): int
    {
        $result = $pruner();

        $this->info("Enrolments: {$result->enrollments}");
        $this->info("Delivered codes: {$result->codes}");
        $this->info("Recovery codes: {$result->recoveryCodes}");
        $this->info("Throttle rows: {$result->attempts}");

        return self::SUCCESS;
    }
}
