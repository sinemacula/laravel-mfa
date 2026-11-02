<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Support\ConsumerMessages;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Raised when a request needs a factor, a level or fresher authentication than
 * it has, carrying what an application needs to answer as RFC 9470 describes.
 *
 * It is a 401 and sets no `WWW-Authenticate` header of its own: the package
 * also serves cookie guards, and the RFC is about a presented access token, so
 * the application chooses the answer and builds the header with
 * `wwwAuthenticate()`, or its own from `maxAge()` and `acrValues()`. Laravel
 * renders it with its message alone; `toArray()` is what an application's own
 * rendering sends.
 *
 * Its message is translated in the locale it is raised in, so a locale
 * middleware must run before `mfa`. The header's description is the shipped
 * English instead: RFC 6750 makes it a developer's diagnostic in a subset of
 * ASCII, which a translation or an application's override of `en` could break.
 *
 * The requirement is the whole effective one, not what is left of it, and it is
 * the authority. `maxAge()` and `acrValues()` are lossy projections of it: each
 * part is bounded on its own, and neither can state multifactor authentication
 * or phishing resistance.
 *
 * The factors are candidates and not a promise: they are what could follow the
 * first factor, not what would meet this requirement, so a refusal asking for
 * AAL2 can offer only an email code. They are summaries, with destinations
 * masked, and Laravel does not report an HTTP exception, so nothing secret
 * reaches a log.
 *
 * `hasConfirmedFactor` is the identity's `isMfaEnabled()`: whether it has a
 * factor that is not pending, one whose stored status is none the package knows
 * included, so a corrupt status is never reported as having no factor. It is no
 * authority to bootstrap. Having none does not mean enrolment is needed, as a
 * multi-factor first factor can meet a requirement, and it is no grant:
 * enrolment has its own checks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InsufficientAuthenticationException extends HttpException
{
    /** @var string The RFC 9470 error code. */
    public const string ERROR = 'insufficient_user_authentication';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Mfa\Factors\FactorSummary>  $offered
     * @param  ?string  $operation
     * @param  bool  $hasConfirmedFactor
     */
    public function __construct(

        /** The whole requirement the request is held to. */
        public readonly Requirement $requirement,

        /** The factors the session could use next, masked. */
        public readonly array $offered = [],

        /** The operation the route names, when it names one. */
        public readonly ?string $operation = null,

        /** Whether the identity has a factor that is not pending. */
        public readonly bool $hasConfirmedFactor = false,
    ) {
        parent::__construct(401, ConsumerMessages::line(ConsumerMessages::FURTHER_AUTHENTICATION_REQUIRED));
    }

    /**
     * The shortest bound of any part, in seconds, or `null` when none is
     * bounded.
     *
     * @return ?int
     */
    public function maxAge(): ?int
    {
        $bounds = array_filter(
            array_map($this->requirement->maxAge(...), $this->requirement->parts()),
            static fn (?int $maxAge): bool => $maxAge !== null,
        );

        return $bounds === [] ? null : min($bounds);
    }

    /**
     * The `acr` values that would meet the requirement's level: its minimum
     * level's value, or none when it asks for none.
     *
     * @return list<string>
     */
    public function acrValues(): array
    {
        $level = $this->requirement->minimumLevel;

        return $level === null ? [] : [$level->value];
    }

    /**
     * What an application's own rendering sends, with every factor masked.
     *
     * @formatter:off
     *
     * @return array{
     *     error: string,
     *     max_age: ?int,
     *     acr_values: list<string>,
     *     requirement: array<string, array<string, int|string|null>>,
     *     operation: ?string,
     *     has_confirmed_factor: bool,
     *     factors: list<array<string, mixed>>,
     * }
     *
     * @formatter:on
     */
    public function toArray(): array
    {
        return [
            'error'                => self::ERROR,
            'max_age'              => $this->maxAge(),
            'acr_values'           => $this->acrValues(),
            'requirement'          => $this->requirement->toArray(),
            'operation'            => $this->operation,
            'has_confirmed_factor' => $this->hasConfirmedFactor,
            'factors'              => array_map(static fn (FactorSummary $factor): array => $factor->jsonSerialize(), $this->offered),
        ];
    }

    /**
     * An RFC 9470 `WWW-Authenticate` value, omitting what the requirement does
     * not state. An adapter that maps levels to `acr` names builds its own from
     * `maxAge()` and `acrValues()`.
     *
     * @param  string  $scheme
     * @return string
     */
    public function wwwAuthenticate(string $scheme = 'Bearer'): string
    {
        $parameters = [
            sprintf('error="%s"', self::ERROR),
            sprintf('error_description="%s"', ConsumerMessages::english(ConsumerMessages::FURTHER_AUTHENTICATION_REQUIRED)),
        ];

        $acrValues = $this->acrValues();

        if ($acrValues !== []) {
            $parameters[] = sprintf('acr_values="%s"', implode(' ', $acrValues));
        }

        $maxAge = $this->maxAge();

        if ($maxAge !== null) {
            $parameters[] = sprintf('max_age="%d"', $maxAge);
        }

        return $scheme . ' ' . implode(', ', $parameters);
    }
}
