<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * What a session must have proved, from the application, a tenant, the identity
 * or an operation: any of an additional verification, multifactor
 * authentication, a minimum assurance level and phishing resistance, each with
 * an optional maximum age in seconds for the proof that satisfies it.
 *
 * Built from `none()` by asking for each part. `strictest()` composes several
 * requirements into one a session meets only when it meets each of them. The
 * serialised form names each part asked for, so a requirement can be stored,
 * configured or carried on an exception, and a mistyped part is refused rather
 * than dropped.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, array<string, int|string|null>>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Requirement implements \JsonSerializable, Arrayable
{
    /**
     * Constructor.
     *
     * @param  array<string, ?int>  $maxAges
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $minimumLevel
     */
    private function __construct(

        /** The parts asked for, keyed by value, each with its maximum age in seconds or `null` for any age. */
        private array $maxAges,

        /** The lowest level that meets the requirement, or `null` when it asks for none. */
        public ?AssuranceLevel $minimumLevel,
    ) {}

    /**
     * The requirement that asks for nothing.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self([], null);
    }

    /**
     * The strictest of the given requirements: every part any of them asks for,
     * the highest minimum level, and for each part the shortest maximum age any
     * of them sets. A session that meets it meets each of them, so the same
     * parts always compose to the same answer, in any order.
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
     * Read a requirement back from its serialised form: each part asked for,
     * keyed by its value, with an optional `max_age` and, for the minimum
     * level, its `level`.
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

            $requirement = $part === RequirementPart::MINIMUM_LEVEL
                ? $requirement->withMinimumLevel($read->enum('level', AssuranceLevel::class), $read->nullableInt('max_age'))
                : $requirement->with($part, $read->nullableInt('max_age'));
        }

        return $requirement;
    }

    /**
     * The requirement with an additional verification asked for: an accepted
     * combination, or a first factor that is a multi-factor authenticator.
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
     * The requirement with multifactor authentication asked for.
     *
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
     * The requirement with a minimum assurance level asked for, in place of any
     * it asked before.
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
     * The requirement with phishing resistance asked for.
     *
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
     * Whether the requirement asks for the given part.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @return bool
     */
    public function asks(RequirementPart $part): bool
    {
        return array_key_exists($part->value, $this->maxAges);
    }

    /**
     * The maximum age in seconds of the proof that satisfies the given part, or
     * `null` when any age will do or the part is not asked for.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @return ?int
     */
    public function maxAge(RequirementPart $part): ?int
    {
        return $this->maxAges[$part->value] ?? null;
    }

    /**
     * The parts the requirement asks for, in a fixed order.
     *
     * @return list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>
     */
    public function parts(): array
    {
        return array_values(array_filter(RequirementPart::cases(), $this->asks(...)));
    }

    /**
     * Whether the requirement asks for nothing.
     *
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->maxAges === [];
    }

    /**
     * The parts asked for, keyed by value in a fixed order, each with its
     * maximum age and, for the minimum level, the level.
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
     * The requirement as JSON serialises it: the same as `toArray()`.
     *
     * @return array<string, array<string, int|string|null>>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * The requirement with the given part asked for, with its maximum age.
     *
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
     * The higher of two minimum levels, where `null` asks for none.
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
     * The stricter of two maximum ages: the shorter, where `null` allows any.
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
