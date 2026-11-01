<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;

/**
 * What a session's proofs add up to: whether the combination is accepted as an
 * additional verification, whether it is multifactor authentication, the
 * assurance level it supports, whether it is phishing-resistant, whether it
 * relies on a restricted authenticator, the `amr` values it reports, and which
 * parts of the outstanding requirement it meets and which it does not.
 *
 * Accepted, multifactor and the level are separate answers: an email code after
 * a password is accepted without being multifactor, and a code after a
 * phone-code sign-in is accepted at AAL1 only. `amr` states only what happened,
 * and is never enough on its own to carry a result.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, mixed>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Evaluation implements \JsonSerializable, Arrayable
{
    /**
     * Constructor.
     *
     * @param  bool  $accepted
     * @param  bool  $multifactor
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  bool  $phishingResistant
     * @param  bool  $restricted
     * @param  list<string>  $amr
     * @param  list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>  $met
     * @param  list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>  $unmet
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Whether the combination is accepted as an additional verification. */
        public bool $accepted,

        /** Whether the combination is multifactor authentication. */
        public bool $multifactor,

        /** The assurance level the combination supports. */
        public AssuranceLevel $level,

        /** Whether the combination is phishing-resistant. */
        public bool $phishingResistant,

        /** Whether the combination relies on a restricted authenticator, such as an SMS code. */
        public bool $restricted,

        /** The RFC 8176 `amr` values the combination reports, derived from what was observed. */
        public array $amr,

        /** The parts of the requirement the combination meets. */
        public array $met,

        /** The parts of the requirement the combination does not meet. */
        public array $unmet,
    ) {
        self::assertAmr($amr);
        self::assertParts($met, $unmet);
    }

    /**
     * Whether the combination meets the whole requirement: no part is unmet.
     *
     * @return bool
     */
    public function meetsRequirement(): bool
    {
        return $this->unmet === [];
    }

    /**
     * The evaluation with snake_case keys and the values of the level and the
     * parts.
     *
     * @return array{accepted: bool, multifactor: bool, level: string, phishing_resistant: bool, restricted: bool, amr: list<string>, met: list<string>, unmet: list<string>}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'accepted'           => $this->accepted,
            'multifactor'        => $this->multifactor,
            'level'              => $this->level->value,
            'phishing_resistant' => $this->phishingResistant,
            'restricted'         => $this->restricted,
            'amr'                => $this->amr,
            'met'                => array_map(static fn (RequirementPart $part): string => $part->value, $this->met),
            'unmet'              => array_map(static fn (RequirementPart $part): string => $part->value, $this->unmet),
        ];
    }

    /**
     * The evaluation as JSON serialises it: the same as `toArray()`.
     *
     * @return array{accepted: bool, multifactor: bool, level: string, phishing_resistant: bool, restricted: bool, amr: list<string>, met: list<string>, unmet: list<string>}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Refuse a blank or repeated `amr` value.
     *
     * @param  list<string>  $amr
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertAmr(array $amr): void
    {
        $seen = [];

        foreach ($amr as $value) {
            if (trim($value) === '') {
                throw new \InvalidArgumentException('An amr value must not be blank.');
            }

            if (isset($seen[$value])) {
                throw new \InvalidArgumentException(sprintf('The amr value [%s] is listed more than once.', $value));
            }

            $seen[$value] = true;
        }
    }

    /**
     * Refuse a part listed twice, or both met and unmet.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>  $met
     * @param  list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>  $unmet
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertParts(array $met, array $unmet): void
    {
        $seen = [];

        foreach ([$met, $unmet] as $list => $parts) {
            foreach ($parts as $part) {
                if (isset($seen[$part->value])) {
                    $problem = $seen[$part->value] === $list ? 'is listed more than once' : 'cannot be both met and unmet';

                    throw new \InvalidArgumentException(sprintf('The [%s] part %s.', $part->value, $problem));
                }

                $seen[$part->value] = $list;
            }
        }
    }
}
