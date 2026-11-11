<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Testing\Seams\SubjectTypeResolverContract;

/**
 * The `SubjectTypeResolver` contract kit; each check delegates to
 * `SubjectTypeResolverContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait SubjectTypeResolverTests
{
    /**
     * @return void
     */
    public function testSubjectTypeResolverFindsAPersonAPerson(): void
    {
        SubjectTypeResolverContract::assertAPersonIsAPerson($this->subjectTypeResolver(), $this->personIdentity());
    }

    /**
     * @return void
     */
    public function testSubjectTypeResolverFindsAMachineNoPerson(): void
    {
        SubjectTypeResolverContract::assertAMachineIsNotAPerson($this->subjectTypeResolver(), $this->machineIdentity());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver
     */
    abstract protected function subjectTypeResolver(): SubjectTypeResolver;

    /**
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    abstract protected function personIdentity(): Authenticatable;

    /**
     * A machine's identity, such as an API client.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    abstract protected function machineIdentity(): Authenticatable;
}
