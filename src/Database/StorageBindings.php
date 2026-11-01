<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Factors\FactorService;

/**
 * Checks, when the package boots, that every configured model lives on the
 * storage connection (see `StorageConnection`), so a deployment that would
 * split a serialised change across two connections fails before it serves a
 * request rather than at a person's first change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StorageBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse a configured model on another connection than the storage one.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidFactorModelException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ModelOffStorageConnectionException
     */
    public static function boot(Application $app): void
    {
        $factorModel = $app->make(FactorService::class)->factorModel();

        StorageConnection::assertHolds(new $factorModel, 'mfa.factor.model');
    }
}
