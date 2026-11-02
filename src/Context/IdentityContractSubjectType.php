<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;

/**
 * The default `SubjectTypeResolver`, which reads the identity contract: an
 * identity is a person only when it implements `MultiFactorAuthenticatable` and
 * says it can hold factors. Anything else, an identity of another kind
 * included, is treated as a machine, which every operation refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentityContractSubjectType implements SubjectTypeResolver
{
    /**
     * Whether the identity is a person.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isPerson(Authenticatable $identity): bool
    {
        return $identity instanceof MultiFactorAuthenticatable && $identity->canHoldFactors();
    }
}
