<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Mfa\Config\ConfigurationValidator;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `mfa:check`: checks the configuration and the bindings it needs the way the
 * package does when it boots, and exits non-zero on a problem, for deploy
 * pipelines and readiness probes.
 *
 * Every check runs, so one run lists every problem, each as
 * `[<subject>] <message>`, and each subject without one as `[<subject>] OK`:
 * the storage connection, the factor model and table, the identity states
 * table, each capability's settings, and each configured application (its
 * settings, a delivery binding for each code type it enables, and its first
 * factor). The package skips its own boot check while this command runs, so the
 * command reports the problems rather than failing on the first. It reads
 * configuration and the container only, opens no database connection and prints
 * no secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: self::NAME)]
final class CheckConfigurationCommand extends Command
{
    /** @var string The command's name. */
    public const string NAME = 'mfa:check';

    /** @var string The name and signature of the console command. */
    protected $signature = self::NAME;

    /** @var string The console command description. */
    protected $description = 'Check the MFA configuration and the bindings it needs';

    /**
     * Check the configuration and report each problem, or that a subject has
     * none.
     *
     * @param  \SineMacula\Laravel\Mfa\Config\ConfigurationValidator  $validator
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function handle(ConfigurationValidator $validator): int
    {
        $failed = false;

        foreach ($validator->report() as $subject => $problems) {

            if ($problems === []) {
                $this->info("[{$subject}] OK");

                continue;
            }

            foreach ($problems as $problem) {
                $this->error("[{$subject}] {$problem}");
            }

            $failed = true;
        }

        return $failed ? self::FAILURE : self::SUCCESS;
    }
}
