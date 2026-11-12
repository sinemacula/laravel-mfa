<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Support\PackageDefault;

/**
 * Container bindings for delivered codes, the default gateway and the default
 * senders.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CodeBindings
{
    /**
     * Disallow instantiation.
     */
    private function __construct() {}

    /**
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        PackageDefault::bind($app, SmsSender::class, NullSmsSender::class);
        PackageDefault::bind($app, EmailSender::class, NullEmailSender::class);
        $app->bindIf(CodeService::class);
        PackageDefault::bind($app, ChallengeGateway::class, PackageChallengeGateway::class);
    }
}
