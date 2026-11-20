<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Mfa\Config\ConfigurationValidator;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Mfa\MfaManager;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `mfa:check`: runs the boot-time configuration checks and exits non-zero on a
 * problem, for deploy pipelines and readiness probes. The boot check is skipped
 * while it runs so every problem is listed. It opens no database connection.
 * Each application's types are checked against the manager's drivers once the
 * rest of the configuration passes, as only then can the manager be built.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: self::NAME)]
final class CheckConfigurationCommand extends Command
{
    /** @var string */
    public const string NAME = 'mfa:check';

    /** @var string */
    protected $signature = self::NAME;

    /** @var string */
    protected $description = 'Check the MFA configuration and the bindings it needs';

    /**
     * @param  \SineMacula\Laravel\Mfa\Config\ConfigurationValidator  $validator
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    public function handle(ConfigurationValidator $validator): int
    {
        $failed = false;

        try {
            $validator->validate();

            $manager = $this->laravel->make('mfa');

            if (!$manager instanceof MfaManager) {
                throw new \LogicException('The [mfa] binding must be the MFA manager.');
            }

            $registered = $manager->hasDriver(...);
        } catch (InvalidConfigurationException) {
            $registered = null;
        }

        foreach ($validator->report($registered) as $subject => $problems) {

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
