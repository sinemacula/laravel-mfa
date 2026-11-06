<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Testing\Seams\EventContextResolverContract;

/**
 * The `EventContextResolver` contract kit: the context is scalar values only; a
 * subject naming no sign-in the resolver knows leaves the session, principal
 * and tenant unknown, even while another session is being served; and, when the
 * test names one, a sign-in the resolver knows names its session.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `EventContextResolverContract`.
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
     * Every value of the context is an integer, a string or `null`.
     *
     * @return void
     */
    public function testEventContextResolverGivesScalarValuesOnly(): void
    {
        EventContextResolverContract::assertGivesScalarValuesOnly($this->eventContextResolver(), $this->eventIdentity());
    }

    /**
     * A subject naming no sign-in, or one the resolver does not know, leaves
     * the session, principal and tenant unknown, while the session
     * `arrangeServedEventSession()` arranges is being served.
     *
     * @return void
     */
    public function testEventContextResolverNamesNoSessionItIsNotGiven(): void
    {
        $this->arrangeServedEventSession();

        EventContextResolverContract::assertNamesNoSessionItIsNotGiven($this->eventContextResolver(), $this->eventIdentity());
    }

    /**
     * A subject naming the sign-in `knownEventSignIn()` gives names its
     * session; a resolver that maps no sign-in has none to give, and the check
     * holds trivially.
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
     * Serve a session of the identity's, as the process would while an event of
     * another is resolved; nothing by default. A resolver over an
     * authentication layer signs the identity in here, so a resolver that read
     * the session being served would be caught.
     *
     * @return void
     */
    protected function arrangeServedEventSession(): void {}

    /**
     * An application and a sign-in on it the resolver knows, as
     * `[application, sign-in]`, or `null` for a resolver that maps no sign-in,
     * as the package's default does.
     *
     * @return ?array{0: string, 1: string}
     */
    protected function knownEventSignIn(): ?array
    {
        return null;
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\EventContextResolver
     */
    abstract protected function eventContextResolver(): EventContextResolver;

    /**
     * An identity events are about.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function eventIdentity(): MultiFactorAuthenticatable;
}
