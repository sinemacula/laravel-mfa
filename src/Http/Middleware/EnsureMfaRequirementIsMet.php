<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Http\Middleware;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Factors\ConfirmedFactors;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Verification\FactorOffers;
use Symfony\Component\HttpFoundation\Response;

/**
 * The route gate: `mfa` lets a request on only when the session the request
 * serves meets its whole requirement, read from the proofs it holds.
 *
 * Bare `mfa` enforces the composed requirement and adds nothing to it, so what
 * `never` and `enrolled` ask nothing of passes, while an identity's part, a
 * tenant's part and a re-enrolment obligation still apply. `mfa:level=aal2`
 * adds a level. `mfa:operation=name` adds the operation's freshness, judged
 * only by the bound `FreshnessGate`; a level has no maximum age, so freshness
 * for a route goes through a named operation. Both may be given together, and
 * separate entries from a group and a route each enforce their own.
 *
 * It refuses, with `InsufficientAuthenticationException`, whoever does not meet
 * it and everyone the package does not serve, also under `never`, since that
 * setting controls the requirement and not who is served: a pending session,
 * which is never answered from the guard's user, a guest, an identity that is
 * not MFA-capable, a machine and an inactive identity. A pending credential
 * that does not validate makes its resolver throw, and that is not disguised as
 * a refusal. A route `ExemptFromMfa` marks is not gated.
 *
 * Parameters are checked first, also on an exempt route, so a typo is loud:
 * each is `key=value`, the keys `level` and `operation`, each once, and
 * anything else is an `InvalidArgumentException`. An operation with no
 * requirement is not a misconfiguration, and is simply never fresh.
 *
 * It only reads. A shortfall is answered and no session changes, so a GET never
 * revokes a credential and a stale operation is a step-up rather than a
 * demotion of the sign-in; a change that causes a shortfall hands it to
 * `SessionTransition` itself (see `Requirements\SessionReevaluation`).
 *
 * It belongs on routes and needs its authentication first, which the package's
 * middleware priority sees to; with no matched route nothing is exempt, so it
 * does not belong in the global stack. Whatever selects the application or the
 * active tenant must run before it too, as a tenant of `null` adds no part, and
 * since it runs before route bindings are substituted, a resolver must not rely
 * on bound route models.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnsureMfaRequirementIsMet
{
    /** @var string The parameter asking for a minimum level. */
    private const string LEVEL = 'level';

    /** @var string The parameter asking for an operation's freshness. */
    private const string OPERATION = 'operation';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the seams and the router are resolved from. */
        private Container $container,
    ) {}

    /**
     * Let the request on when the session it serves meets the requirement, or
     * when its route is exempt.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @param  string  ...$parameters
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     */
    public function handle(Request $request, \Closure $next, string ...$parameters): Response
    {
        [$level, $operation] = self::parse($parameters);

        if ($this->isExempt($request)) {
            return $next($request);
        }

        $context = CallerContext::fromRequest($request, null, $this->container);
        $callers = $this->container->make(CallerContextResolver::class);
        $pending = $context->pending;

        if ($pending !== null) {
            throw $this->refusal($context, Requirement::strictest($pending->requirement, $level), $operation, $this->hasConfirmedFactor($pending->identity));
        }

        $caller = $callers->resolve($context, null) ?? throw $this->refusal($context, $level, $operation, false);

        return $this->gate($request, $next, $caller, $callers->application($caller), $level, $operation);
    }

    /**
     * Let a caller the package serves on when it meets the requirement.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Symfony\Component\HttpFoundation\Response  $next
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $level
     * @param  ?string  $operation
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function gate(Request $request, \Closure $next, Caller $caller, string $application, Requirement $level, ?string $operation): Response
    {
        $requirements = $this->container->make(RequirementService::class);
        $requirement  = Requirement::strictest($requirements->requirementFor($caller->identity, $application), $level);

        if ($this->isMet($caller, $application, $requirement, $requirements, $operation)) {
            return $next($request);
        }

        $freshness = $operation === null ? null : $requirements->freshnessRequirement($caller->context(), $operation);

        throw $this->refusal($caller->context(), Requirement::strictest($requirement, $freshness ?? Requirement::none()), $operation, $this->hasConfirmedFactor($caller->identity));
    }

    /**
     * Whether the caller is active, its proofs meet the requirement and the
     * bound gate finds it fresh for the operation, if one is named.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Requirements\RequirementService  $requirements
     * @param  ?string  $operation
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function isMet(Caller $caller, string $application, Requirement $requirement, RequirementService $requirements, ?string $operation): bool
    {
        if (!$caller->identity->isMfaActive()) {
            return false;
        }

        $proofs = $this->container->make(SessionFirstFactor::class)->proofs($caller->identity, $application);

        return $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs)->meetsRequirement()
            && ($operation === null || $requirements->isFresh($caller->context(), $operation));
    }

    /**
     * Whether the route's resolved middleware holds the exempt marker: read
     * from the route, not the request, so the order the two run in does not
     * matter and a request cannot claim it. With no matched route nothing is
     * exempt.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isExempt(Request $request): bool
    {
        $route = $request->route();

        return $route instanceof Route
            && in_array(ExemptFromMfa::class, $this->container->make(Router::class)->gatherRouteMiddleware($route), true);
    }

    /**
     * The refusal of the request.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  ?string  $operation
     * @param  bool  $hasConfirmedFactor
     * @return \SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function refusal(CallerContext $context, Requirement $requirement, ?string $operation, bool $hasConfirmedFactor): InsufficientAuthenticationException
    {
        return new InsufficientAuthenticationException($requirement, $this->container->make(FactorOffers::class)->offered($context), $operation, $hasConfirmedFactor);
    }

    /**
     * Determine whether the identity has a factor whose stored status is
     * exactly `confirmed`, for the refusal to report as a fact (see
     * `Factors\ConfirmedFactors`).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function hasConfirmedFactor(MultiFactorAuthenticatable $identity): bool
    {
        return ConfirmedFactors::isHeldBy($identity, $this->container->make(Repository::class));
    }

    /**
     * The level part and the operation the parameters ask for.
     *
     * @param  array<array-key, string>  $parameters
     * @return array{\SineMacula\Laravel\Mfa\Requirements\Requirement, ?string}
     *
     * @throws \InvalidArgumentException
     */
    private static function parse(array $parameters): array
    {
        $values = [];

        foreach ($parameters as $parameter) {
            [$key, $value] = self::pair($parameter);

            if (array_key_exists($key, $values)) {
                throw new \InvalidArgumentException(sprintf('The mfa middleware was given [%s] more than once.', $key));
            }

            $values[$key] = $value;
        }

        return [self::levelPart($values[self::LEVEL] ?? null), self::operationName($values[self::OPERATION] ?? null)];
    }

    /**
     * The key and value of one parameter, refusing anything but one known key
     * and one value, which `levelPart()` and `operationName()` go on to check.
     *
     * @param  string  $parameter
     * @return array{string, string}
     *
     * @throws \InvalidArgumentException
     */
    private static function pair(string $parameter): array
    {
        $parts = explode('=', $parameter);

        if (count($parts) !== 2 || !in_array($parts[0], [self::LEVEL, self::OPERATION], true)) {
            throw new \InvalidArgumentException(sprintf('The mfa middleware takes level=<level> and operation=<name>; got [%s].', $parameter));
        }

        return [$parts[0], $parts[1]];
    }

    /**
     * The requirement the level asks for: nothing when none is named.
     *
     * @param  ?string  $level
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    private static function levelPart(?string $level): Requirement
    {
        if ($level === null) {
            return Requirement::none();
        }

        $named = AssuranceLevel::tryFrom($level) ?? throw new \InvalidArgumentException(sprintf('The mfa middleware was given [%s], which is not a level.', $level));

        return Requirement::none()->withMinimumLevel($named);
    }

    /**
     * The operation's name, refusing one not in the form a name takes.
     *
     * @param  ?string  $operation
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function operationName(?string $operation): ?string
    {
        if ($operation !== null && !Operation::isName($operation)) {
            throw new \InvalidArgumentException(sprintf('The mfa middleware was given [%s], which is not in the form an operation\'s name takes.', $operation));
        }

        return $operation;
    }
}
