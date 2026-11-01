<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

/**
 * Registers the delivered code service and the default SMS and email senders,
 * which throw until the application binds its own; the package refuses to boot
 * with an application that enables a code type while its sender is still the
 * default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CodeBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Register the code service and the default senders. The engine needs no
     * binding: the container builds a fresh one each time it is resolved.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->singleton(SmsSender::class, NullSmsSender::class);
        $app->singleton(EmailSender::class, NullEmailSender::class);
        $app->singleton(CodeService::class);
    }
}
