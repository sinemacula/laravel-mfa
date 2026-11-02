<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Http;

use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Test double for `MfaManager` used by the `RequireMfa` middleware tests.
 *
 * Extends the real manager so the facade's `@method` assertions line up, but
 * bypasses the container-backed Manager constructor — we only poke the handful
 * of methods the middleware actually invokes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FakeMfaManager extends MfaManager // @phpstan-ignore-line
{
    /** @var \SineMacula\Laravel\Mfa\Requirements\Requirement The requirement of the current sign-in: an additional verification unless a test sets another. */
    public Requirement $requirement;

    /** @var list<\SineMacula\Laravel\Mfa\Proofs\Proof> */
    public array $proofs = [];

    /** @var list<\SineMacula\Laravel\Mfa\Factors\FactorSummary> The factors listed: one confirmed unless a test sets others. */
    public array $listed;

    /**
     * Intentionally skip parent::__construct so the fixture can be instantiated
     * outside a bootstrapped Laravel container — the middleware tests only
     * exercise the overridden read methods, none of which touch the manager's
     * container-backed driver registry.
     *
     * @return void
     *
     * @phpstan-ignore constructor.missingParentCall
     */
    public function __construct()
    {
        $this->requirement = Requirement::none()->withAdditionalVerification();
        $this->listed      = [new FactorSummary('id-1', 'totp', null, null, FactorStatus::CONFIRMED, false, null)];
    }

    /**
     * Return the seeded requirement of the current sign-in.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirement(): Requirement
    {
        return $this->requirement;
    }

    /**
     * Return the seeded proofs of the current sign-in.
     *
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    #[\Override]
    public function proofs(): array
    {
        return $this->proofs;
    }

    /**
     * Return the seeded factors.
     *
     * @return list<\SineMacula\Laravel\Mfa\Factors\FactorSummary>
     */
    #[\Override]
    public function factors(): array
    {
        return $this->listed;
    }
}
