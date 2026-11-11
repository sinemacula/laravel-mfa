<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;

/**
 * What a session's proofs add up to. Accepted, multifactor and level are
 * separate answers: an email code after a password is accepted without being
 * multifactor, and `amr` alone never carries a result.
 *
 * A self-contradicting evaluation is refused on construction, so a replaced
 * combination policy cannot report more than it found. `metUntil` and
 * `multifactorAt` are answers about now, so serialisation omits them.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, mixed>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Evaluation implements \JsonSerializable, Arrayable
{
    /** @var string */
    private const string AMR_MULTIFACTOR = 'mfa';

    /** @var string An accepted additional verification that is not multifactor. */
    private const string AMR_MULTIPLE_CHANNEL = 'mca';

    /**
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

        /** Accepted as an additional verification. */
        public bool $accepted,

        /** Multifactor authentication. */
        public bool $multifactor,

        /** The assurance level supported. */
        public AssuranceLevel $level,

        /** Phishing-resistant. */
        public bool $phishingResistant,

        /** Relies on a restricted authenticator, such as an SMS code. */
        public bool $restricted,

        /** RFC 8176 values derived from what was observed. */
        public array $amr,

        /** Requirement parts met. */
        public array $met,

        /** Requirement parts not met. */
        public array $unmet,

        /** When the first age-bounded part lapses; sets an enrolment grant's lifetime. */
        public ?CarbonImmutable $metUntil = null,

        /** When the freshest multifactor evidence was made; `null` when unknown. */
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
     * No part is unmet.
     *
     * @return bool
     */
    public function meetsRequirement(): bool
    {
        return $this->unmet === [];
    }

    /**
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
     * Refuse a part reported met that the evaluation's own answers rule out.
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
