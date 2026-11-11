<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Http\Middleware;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\StepUpRefusal;
use Symfony\Component\HttpFoundation\Response;

/**
 * The `mfa` route gate: lets a request on only when its session's proofs meet
 * the whole composed requirement. `level=<level>` adds a minimum level and
 * `operation=<name>` an operation's freshness; any other parameter throws, even
 * on an exempt route.
 *
 * Pending sessions, guests, identities that are not MFA-capable, machines and
 * inactive identities are refused, also under `never`. It only reads, so a
 * shortfall changes no session. It belongs on routes, after authentication and
 * whatever selects the application or tenant; route bindings are not yet
 * substituted when it runs.
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
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Seams are resolved per call, so the gate holds no state. */
        private Container $container,
    ) {}

    /**
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
            throw $this->refusal($context, Requirement::strictest($pending->requirement, $level), $operation);
        }

        $caller = $callers->resolve($context, null) ?? throw $this->refusal($context, $level, $operation);

        return $this->gate($request, $next, $caller, $callers->application($caller), $level, $operation);
    }

    /**
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

        throw $this->refusal($caller->context(), Requirement::strictest($requirement, $freshness ?? Requirement::none()), $operation);
    }

    /**
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
        if (!$this->container->make(ActiveStateResolver::class)->isActive($caller->identity)) {
            return false;
        }

        $proofs = $this->container->make(SessionFirstFactor::class)->proofs($caller->identity, $application);

        return $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs)->meetsRequirement()
            && ($operation === null || $requirements->isFresh($caller->context(), $operation));
    }

    /**
     * Read from the route, not the request, so middleware order does not matter
     * and a request cannot claim it.
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
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  ?string  $operation
     * @return \SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function refusal(CallerContext $context, Requirement $requirement, ?string $operation): InsufficientAuthenticationException
    {
        return $this->container->make(StepUpRefusal::class)->of($context, $requirement, $operation);
    }

    /**
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
     * Refuses anything but one known key and one value.
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
