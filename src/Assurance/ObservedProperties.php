<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * What a proof actually observed. `null` means not observed; nothing is
 * inferred from a factor's type or configuration.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, bool|string|null>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ObservedProperties implements \JsonSerializable, Arrayable
{
    /**
     * @param  ?bool  $userPresence
     * @param  ?bool  $userVerification
     * @param  ?bool  $backupEligibility
     * @param  ?bool  $backupState
     * @param  ?bool  $phishingResistance
     * @param  ?\SineMacula\Laravel\Mfa\Enums\KeyProtection  $keyProtection
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** WebAuthn UP. */
        public ?bool $userPresence = null,

        /** WebAuthn UV. */
        public ?bool $userVerification = null,

        /** WebAuthn BE. */
        public ?bool $backupEligibility = null,

        /** WebAuthn BS. */
        public ?bool $backupState = null,

        /** True for an origin-bound WebAuthn assertion. */
        public ?bool $phishingResistance = null,

        /** How the credential's key was protected. */
        public ?KeyProtection $keyProtection = null,
    ) {
        if ($backupEligibility === false && $backupState === true) {
            throw new \InvalidArgumentException('A credential cannot be observed backed up when it was observed as not eligible for backup.');
        }
    }

    /**
     * @return self
     */
    public static function none(): self
    {
        return new self;
    }

    /**
     * A missing key reads as not observed; an unknown key is refused.
     *
     * @param  array<array-key, mixed>  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        $fields = new SerializedFields($data, 'serialised observed properties');

        $fields->refuseUnknown('user_presence', 'user_verification', 'backup_eligibility', 'backup_state', 'phishing_resistance', 'key_protection');

        return new self(
            $fields->nullableBool('user_presence'),
            $fields->nullableBool('user_verification'),
            $fields->nullableBool('backup_eligibility'),
            $fields->nullableBool('backup_state'),
            $fields->nullableBool('phishing_resistance'),
            $fields->nullableEnum('key_protection', KeyProtection::class),
        );
    }

    /**
     * @return array{user_presence: ?bool, user_verification: ?bool, backup_eligibility: ?bool, backup_state: ?bool, phishing_resistance: ?bool, key_protection: ?string}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'user_presence'       => $this->userPresence,
            'user_verification'   => $this->userVerification,
            'backup_eligibility'  => $this->backupEligibility,
            'backup_state'        => $this->backupState,
            'phishing_resistance' => $this->phishingResistance,
            'key_protection'      => $this->keyProtection?->value,
        ];
    }

    /**
     * @return array{user_presence: ?bool, user_verification: ?bool, backup_eligibility: ?bool, backup_state: ?bool, phishing_resistance: ?bool, key_protection: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
