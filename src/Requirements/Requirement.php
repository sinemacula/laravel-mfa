<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * What a session must have proved, each part with an optional maximum age in
 * seconds; serialised parts and fields are strictly checked.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, array<string, int|string|null>>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Requirement implements \JsonSerializable, Arrayable
{
    /**
     * @param  array<string, ?int>  $maxAges
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $minimumLevel
     */
    private function __construct(

        /** Maximum age in seconds per part asked for, `null` for any age. */
        private array $maxAges,

        /** `null` when no minimum level is asked for. */
        public ?AssuranceLevel $minimumLevel,
    ) {}

    /**
     * @return self
     */
    public static function none(): self
    {
        return new self([], null);
    }

    /**
     * Every part any asks for, the highest minimum level and the shortest
     * maximum age, so the result is the same in any order.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  ...$parts
     * @return self
     */
    public static function strictest(self ...$parts): self
    {
        $maxAges = [];
        $level   = null;

        foreach ($parts as $requirement) {
            foreach ($requirement->maxAges as $part => $maxAge) {
                $maxAges[$part] = self::shorter($maxAges[$part] ?? $maxAge, $maxAge);
            }

            $level = self::higher($level, $requirement->minimumLevel);
        }

        return new self($maxAges, $level);
    }

    /**
     * An unknown part or field is refused, so a typo never drops a maximum age.
     *
     * @param  array<array-key, mixed>  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        $requirement = self::none();
        $fields      = new SerializedFields($data, 'a serialised requirement');

        foreach (array_keys($data) as $key) {
            $part = RequirementPart::tryFrom((string) $key) ?? throw new \InvalidArgumentException(sprintf('The [%s] part of a serialised requirement is not a known part.', $key));
            $read = new SerializedFields($fields->array($part->value), sprintf('the [%s] part of a serialised requirement', $part->value));

            $read->refuseUnknown(...self::fieldsOf($part));

            $requirement = $part === RequirementPart::MINIMUM_LEVEL
                ? $requirement->withMinimumLevel($read->enum('level', AssuranceLevel::class), $read->nullableInt('max_age'))
                : $requirement->with($part, $read->nullableInt('max_age'));
        }

        return $requirement;
    }

    /**
     * An accepted combination, or a first factor that is a multi-factor
     * authenticator.
     *
     * @param  ?int  $maxAge
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withAdditionalVerification(?int $maxAge = null): self
    {
        return $this->with(RequirementPart::ADDITIONAL_VERIFICATION, $maxAge);
    }

    /**
     * @param  ?int  $maxAge
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withMultifactor(?int $maxAge = null): self
    {
        return $this->with(RequirementPart::MULTIFACTOR, $maxAge);
    }

    /**
     * Replaces any minimum level asked before.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  ?int  $maxAge
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withMinimumLevel(AssuranceLevel $level, ?int $maxAge = null): self
    {
        if ($level === AssuranceLevel::UNCLASSIFIED) {
            throw new \InvalidArgumentException('A requirement cannot ask for the [unclassified] level.');
        }

        return new self($this->with(RequirementPart::MINIMUM_LEVEL, $maxAge)->maxAges, $level);
    }

    /**
     * @param  ?int  $maxAge
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withPhishingResistance(?int $maxAge = null): self
    {
        return $this->with(RequirementPart::PHISHING_RESISTANCE, $maxAge);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @return bool
     */
    public function asks(RequirementPart $part): bool
    {
        return array_key_exists($part->value, $this->maxAges);
    }

    /**
     * In seconds, or `null` when any age will do or the part is not asked for.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @return ?int
     */
    public function maxAge(RequirementPart $part): ?int
    {
        return $this->maxAges[$part->value] ?? null;
    }

    /**
     * In a fixed order.
     *
     * @return list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>
     */
    public function parts(): array
    {
        return array_values(array_filter(RequirementPart::cases(), $this->asks(...)));
    }

    /**
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->maxAges === [];
    }

    /**
     * Keyed by part in a fixed order, each with its maximum age and, for the
     * minimum level, the level.
     *
     * @return array<string, array<string, int|string|null>>
     */
    #[\Override]
    public function toArray(): array
    {
        $parts = [];

        foreach ($this->parts() as $part) {
            $parts[$part->value] = $part === RequirementPart::MINIMUM_LEVEL
                ? ['level' => $this->minimumLevel?->value, 'max_age' => $this->maxAge($part)]
                : ['max_age' => $this->maxAge($part)];
        }

        return $parts;
    }

    /**
     * @return array<string, array<string, int|string|null>>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @param  ?int  $maxAge
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    private function with(RequirementPart $part, ?int $maxAge): self
    {
        if ($maxAge !== null && $maxAge < 1) {
            throw new \InvalidArgumentException('The maximum age of a requirement part must be at least one second.');
        }

        return new self([$part->value => $maxAge] + $this->maxAges, $this->minimumLevel);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @return list<string>
     */
    private static function fieldsOf(RequirementPart $part): array
    {
        return $part === RequirementPart::MINIMUM_LEVEL ? ['level', 'max_age'] : ['max_age'];
    }

    /**
     * `null` asks for no level.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $current
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $candidate
     * @return ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel
     */
    private static function higher(?AssuranceLevel $current, ?AssuranceLevel $candidate): ?AssuranceLevel
    {
        if ($current === null || $candidate === null) {
            return $current ?? $candidate;
        }

        return $current->meets($candidate) ? $current : $candidate;
    }

    /**
     * `null` allows any age.
     *
     * @param  ?int  $current
     * @param  ?int  $candidate
     * @return ?int
     */
    private static function shorter(?int $current, ?int $candidate): ?int
    {
        if ($current === null || $candidate === null) {
            return $current ?? $candidate;
        }

        return min($current, $candidate);
    }
}
