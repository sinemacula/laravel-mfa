<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Container\Container;
use Illuminate\Contracts\Session\Session;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\SyncJob;

/**
 * Starts every queued job with no proofs in the worker's session, leaving
 * `sync` jobs to the request that dispatched them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ForgetProofsBeforeJob
{
    /**
     * Handle the `JobProcessing` event.
     *
     * @param  \Illuminate\Queue\Events\JobProcessing  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(JobProcessing $event): void
    {
        $container = Container::getInstance();

        if ($event->job instanceof SyncJob || !$container->resolved(Session::class)) {
            return;
        }

        $container->make(Session::class)->forget(SessionProofStore::SESSION_KEY);
    }
}
