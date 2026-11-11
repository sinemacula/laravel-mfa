<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Support\ConsumerMessages;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * An RFC 9470 401 for a request that needs more authentication. It sets no
 * `WWW-Authenticate` header, as cookie guards use it too; see
 * `wwwAuthenticate()`.
 *
 * The message is translated, so locale middleware must run before `mfa`; the
 * header's description stays English, as RFC 6750 limits it to ASCII.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InsufficientAuthenticationException extends HttpException
{
    /** @var string The RFC 9470 error code. */
    public const string ERROR = 'insufficient_user_authentication';

    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Mfa\Factors\FactorSummary>  $offered
     * @param  ?string  $operation
     * @param  bool  $hasConfirmedFactor
     */
    public function __construct(

        /** The whole effective requirement, not what is left of it. */
        public readonly Requirement $requirement,

        /** Candidates that could follow the first factor, not a promise to meet the requirement. */
        public readonly array $offered = [],

        /** The operation the route names, when it names one. */
        public readonly ?string $operation = null,

        /** A fact, not a grant: enrolment has its own checks. */
        public readonly bool $hasConfirmedFactor = false,
    ) {
        parent::__construct(401, ConsumerMessages::line(ConsumerMessages::FURTHER_AUTHENTICATION_REQUIRED));
    }

    /**
     * The shortest bound of any part, in seconds. A lossy projection of the
     * requirement.
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
     * The minimum level's `acr` value, if any. A lossy projection of the
     * requirement.
     *
     * @return list<string>
     */
    public function acrValues(): array
    {
        $level = $this->requirement->minimumLevel;

        return $level === null ? [] : [$level->value];
    }

    /**
     * What an application's own rendering sends; Laravel's uses the message.
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
     * not state.
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
