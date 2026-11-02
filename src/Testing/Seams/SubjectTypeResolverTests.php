<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;

/**
 * The `SubjectTypeResolver` contract kit: a person is a person, and a machine
 * is not.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `SubjectTypeResolverContract`.
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
     * A person's identity is a person.
     *
     * @return void
     */
    public function testSubjectTypeResolverFindsAPersonAPerson(): void
    {
        SubjectTypeResolverContract::assertAPersonIsAPerson($this->subjectTypeResolver(), $this->personIdentity());
    }

    /**
     * A machine's identity is not a person.
     *
     * @return void
     */
    public function testSubjectTypeResolverFindsAMachineNoPerson(): void
    {
        SubjectTypeResolverContract::assertAMachineIsNotAPerson($this->subjectTypeResolver(), $this->machineIdentity());
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver
     */
    abstract protected function subjectTypeResolver(): SubjectTypeResolver;

    /**
     * A person's identity.
     *
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
