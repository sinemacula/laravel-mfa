<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Carbon\CarbonImmutable;
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
 * An evaluation that contradicts itself is refused when it is built: a part
 * reported met that its own answers rule out, `mfa` without a multifactor
 * combination, or `mca` without an accepted one that is not multifactor. A
 * replaced combination policy therefore cannot report more than it found.
 *
 * When every part is met, `metUntil` says when the evidence stops meeting them:
 * the instant the first part bounded by a maximum age falls out of it. It is
 * what an enrolment grant's lifetime is taken from, and an answer about now, so
 * neither `toArray()` nor JSON shows it. When the combination is multifactor,
 * `multifactorAt` says when the freshest evidence of that was made: a further
 * proof's own time only when it supplies or completes the multifactor evidence,
 * never when the first factor alone gives it. A policy that does not say leaves
 * it `null`, and nothing then takes a proof to have refreshed it. Neither
 * `toArray()` nor JSON shows it either.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, mixed>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Evaluation implements \JsonSerializable, Arrayable
{
    /** @var string The `amr` value of multifactor authentication. */
    private const string AMR_MULTIFACTOR = 'mfa';

    /** @var string The `amr` value of an accepted additional verification that is not multifactor. */
    private const string AMR_MULTIPLE_CHANNEL = 'mca';

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
     * @param  ?\Carbon\CarbonImmutable  $metUntil
     * @param  ?\Carbon\CarbonImmutable  $multifactorAt
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

        /** When the evidence stops meeting the whole requirement, if a maximum age bounds it. */
        public ?CarbonImmutable $metUntil = null,

        /** When the freshest evidence that the proofs are multifactor was made, when they are and it is known. */
        public ?CarbonImmutable $multifactorAt = null,
    ) {
        self::assertAmr($amr);
        self::assertParts($met, $unmet);

        if ($metUntil !== null && $unmet !== []) {
            throw new \InvalidArgumentException('An evaluation with an unmet part cannot say when it stops meeting the requirement.');
        }

        if ($multifactorAt !== null && !$multifactor) {
            throw new \InvalidArgumentException('An evaluation that is not multifactor cannot say when its multifactor evidence was made.');
        }

        $this->assertMet();
        $this->assertReservedAmr();
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
        foreach ($amr as $index => $value) {
            if (trim($value) === '') {
                throw new \InvalidArgumentException('An amr value must not be blank.');
            }

            if (array_search($value, $amr, true) !== $index) {
                throw new \InvalidArgumentException(sprintf('The amr value [%s] is listed more than once.', $value));
            }
        }
    }

    /**
     * Refuse a part reported met that the evaluation's own answers rule out: an
     * additional verification without an accepted or multifactor combination,
     * multifactor authentication or phishing resistance the combination does
     * not have, or a minimum level when the level is unclassified, which meets
     * none.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertMet(): void
    {
        foreach ($this->met as $part) {
            $possible = match ($part) {
                RequirementPart::ADDITIONAL_VERIFICATION => $this->accepted || $this->multifactor,
                RequirementPart::MULTIFACTOR             => $this->multifactor,
                RequirementPart::MINIMUM_LEVEL           => $this->level !== AssuranceLevel::UNCLASSIFIED,
                RequirementPart::PHISHING_RESISTANCE     => $this->phishingResistant,
            };

            if (!$possible) {
                throw new \InvalidArgumentException(sprintf('The [%s] part cannot be met by a combination that does not provide it.', $part->value));
            }
        }
    }

    /**
     * Refuse `mfa` unless the combination is multifactor, and `mca` unless it
     * is an accepted additional verification that is not.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertReservedAmr(): void
    {
        if (in_array(self::AMR_MULTIFACTOR, $this->amr, true) && !$this->multifactor) {
            throw new \InvalidArgumentException('The amr value [mfa] needs a multifactor combination.');
        }

        if (in_array(self::AMR_MULTIPLE_CHANNEL, $this->amr, true) && (!$this->accepted || $this->multifactor)) {
            throw new \InvalidArgumentException('The amr value [mca] needs an accepted combination that is not multifactor.');
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
