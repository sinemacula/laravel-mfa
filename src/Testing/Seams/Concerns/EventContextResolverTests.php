<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Testing\Seams\EventContextResolverContract;

/**
 * The `EventContextResolver` contract kit; each check delegates to
 * `EventContextResolverContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait EventContextResolverTests
{
    /**
     * @return void
     */
    public function testEventContextResolverGivesScalarValuesOnly(): void
    {
        EventContextResolverContract::assertGivesScalarValuesOnly($this->eventContextResolver(), $this->eventIdentity());
    }

    /**
     * Holds while the session `arrangeServedEventSession()` arranges is served.
     *
     * @return void
     */
    public function testEventContextResolverNamesNoSessionItIsNotGiven(): void
    {
        $this->arrangeServedEventSession();

        EventContextResolverContract::assertNamesNoSessionItIsNotGiven($this->eventContextResolver(), $this->eventIdentity());
    }

    /**
     * Holds trivially when `knownEventSignIn()` is `null`.
     *
     * @return void
     */
    public function testEventContextResolverNamesTheSessionOfAKnownSignIn(): void
    {
        $known = $this->knownEventSignIn();

        if ($known === null) {
            $this->addToAssertionCount(1);

            return;
        }

        EventContextResolverContract::assertNamesTheSessionOfAKnownSignIn($this->eventContextResolver(), $this->eventIdentity(), $known[0], $known[1]);
    }

    /**
     * Serve a session of the identity's; nothing by default. A resolver over an
     * authentication layer signs in here, so reading the served session shows.
     *
     * @return void
     */
    protected function arrangeServedEventSession(): void {}

    /**
     * `[application, sign-in]` the resolver knows, or `null` when it maps none.
     *
     * @return ?array{0: string, 1: string}
     */
    protected function knownEventSignIn(): ?array
    {
        return null;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\EventContextResolver
     */
    abstract protected function eventContextResolver(): EventContextResolver;

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function eventIdentity(): MultiFactorAuthenticatable;
}
