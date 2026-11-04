<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;

/**
 * Factor change gate contract.
 *
 * Whether an active session may make a change to the identity's factors now:
 * enrolling its first additional factor, enrolling a further one, removing one,
 * or generating recovery codes. It is the one place that freshness is judged
 * for those changes, so an adapter that binds it to its authentication layer's
 * own gate replaces the package's judgement rather than adding a second one.
 *
 * It is asked inside the identity's factor state transaction, on the storage
 * connection, after the package's locks, with the factors as stored under them:
 * an implementation may lock its own rows there (an authentication layer's
 * session row, say) in the lock order identity state, factors, then its own. It
 * is never asked before the lock, nor when an enrolment is confirmed: a grant's
 * lifetime already ends with the authorisation that made it. A pending
 * session's bootstrap enrolment is not a change made here.
 *
 * The request carries the requirement the application configures for the
 * change's operation, which an implementation must hold the session to as well
 * as its own policy, the stricter applying; a first additional factor carries
 * none. The factor a removal names must never count towards its own removal.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FactorChangeGate
{
    /**
     * Authorise the change, and say until when the authorisation lasts.
     *
     * Returning means the change is allowed. For a change that is a grant
     * (`FactorChange::isGrant()`), the instant returned is when the grant ends,
     * and the package refuses the change when it is `null` or not in the
     * future; for any other change it may be `null`. A refusal is an
     * `OperationRefusedException` carrying the reason (`not_fresh` when the
     * session is not fresh enough), never a return, so the change rolls back
     * with it. Any other throwable propagates to the caller.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function authorize(FactorChangeRequest $request): ?CarbonImmutable;
}
