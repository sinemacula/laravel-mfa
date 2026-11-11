<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

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
        $app->bindIf(SmsSender::class, NullSmsSender::class);
        $app->bindIf(EmailSender::class, NullEmailSender::class);
        $app->bindIf(CodeService::class);
        $app->bindIf(ChallengeGateway::class, PackageChallengeGateway::class);
    }
}
