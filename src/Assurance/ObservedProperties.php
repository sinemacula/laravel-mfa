<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * The properties a proof actually observed: user presence, user verification,
 * backup eligibility, backup state, phishing resistance and key protection.
 *
 * `null` means the property was not observed, and nothing defaults to true:
 * levels, `amr` values and context keys are derived from what was observed,
 * never inferred from a factor's type or from configuration. A TOTP code
 * observes none of them; a passkey assertion reports what its authenticator
 * data showed.
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, bool|string|null>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ObservedProperties implements \JsonSerializable, Arrayable
{
    /**
     * Constructor.
     *
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

        /** Whether the person was seen to be present (WebAuthn UP). */
        public ?bool $userPresence = null,

        /** Whether the person was verified by the authenticator (WebAuthn UV). */
        public ?bool $userVerification = null,

        /** Whether the credential may be backed up (WebAuthn BE). */
        public ?bool $backupEligibility = null,

        /** Whether the credential is backed up (WebAuthn BS). */
        public ?bool $backupState = null,

        /** Whether the proof resisted phishing, as a WebAuthn assertion bound to its origin does. */
        public ?bool $phishingResistance = null,

        /** How the credential's key was protected. */
        public ?KeyProtection $keyProtection = null,
    ) {
        if ($backupEligibility === false && $backupState === true) {
            throw new \InvalidArgumentException('A credential cannot be observed backed up when it was observed as not eligible for backup.');
        }
    }

    /**
     * The properties of a proof that observed nothing.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self;
    }

    /**
     * Read the properties back from their serialised form. A missing key reads
     * as not observed.
     *
     * @param  array<array-key, mixed>  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        $fields = new SerializedFields($data, 'serialised observed properties');

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
     * The properties with snake_case keys, `null` for what was not observed.
     *
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
     * The properties as JSON serialises them: the same as `toArray()`.
     *
     * @return array{user_presence: ?bool, user_verification: ?bool, backup_eligibility: ?bool, backup_state: ?bool, phishing_resistance: ?bool, key_protection: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
