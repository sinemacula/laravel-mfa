<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;

/**
 * What every `SubjectTypeResolver` must guarantee, as assertions: a person is a
 * person, and a machine is not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class SubjectTypeResolverContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A person's identity is a person.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver  $resolver
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $person
     * @return void
     */
    public static function assertAPersonIsAPerson(SubjectTypeResolver $resolver, Authenticatable $person): void
    {
        Assert::assertTrue($resolver->isPerson($person), 'A person\'s identity must be a person.');
    }

    /**
     * A machine's identity is not a person.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver  $resolver
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $machine
     * @return void
     */
    public static function assertAMachineIsNotAPerson(SubjectTypeResolver $resolver, Authenticatable $machine): void
    {
        Assert::assertFalse($resolver->isPerson($machine), 'A machine\'s identity must not be a person.');
    }
}
