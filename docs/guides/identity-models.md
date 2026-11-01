# Identity Models

## Adopting the package

An identity model implements `Contracts\MultiFactorAuthenticatable` and uses `Concerns\HasFactors`:

```php
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

class AppUser extends User implements MultiFactorAuthenticatable
{
    use HasFactors;
}
```

The trait gives the model everything the contract asks:

| Method                       | Default                                                                   |
|------------------------------|---------------------------------------------------------------------------|
| `authFactors()`              | The identity's factors, of the configured factor model                    |
| `isMfaEnabled()`             | Whether the identity has a confirmed factor; a pending one does not count |
| `canHoldFactors()`           | `true`: the identity is a person                                          |
| `isMfaActive()`              | `true`: every identity the guard returns is active                        |
| `requiresAdditionalFactor()` | `null`: the identity requires nothing of its own sign-ins                 |

Factors belong to the identity, never to a principal or a tenant: one set per person, used in every application. The
owner is polymorphic, by the model's morph class (so an application's morph map is honoured) and its key, which may be
an integer, a UUID or a ULID.

## People and machines

Only a person may hold factors. Override `canHoldFactors()` on a model that also stands for API clients or service
accounts, so every operation refuses them with the failure reason `machine_identity`:

```php
public function canHoldFactors(): bool
{
    return $this->type === 'person';
}
```

With an authentication layer, the adapter answers it from that layer's subject type.

## Active identities

An inactive identity cannot enrol, verify or use a recovery code: every operation refuses it with `identity_inactive`.
Alone, the identity model answers, and the default treats every identity the guard returns as active. Override
`isMfaActive()` where the model knows better:

```php
public function isMfaActive(): bool
{
    return $this->suspended_at === null;
}
```

## Requirements of the identity's own

An identity may require an additional factor of every sign-in, whatever the application asks, for example platform
staff. Return a `Requirements\Requirement` from `requiresAdditionalFactor()`; it is composed with the application's, a
re-enrolment obligation's, a tenant's and an operation's requirement, the strictest of each part applying (see
[Requirements and step-up](requirements.md)):

```php
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

public function requiresAdditionalFactor(): ?Requirement
{
    return $this->is_staff ? Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2) : null;
}
```

[Proofs, assurance and requirements](assurance.md) describes requirements.

## Deleting an identity

Deleting the model deletes everything the package holds for it: its factors, its enrolments in progress, its delivered
codes, its recovery codes, its passkey associations and its factor state. The trait does it on the model's `deleted`
event, once the identity's row is gone, through `Lifecycle\ForgetIdentity`, in the identity's factor state transaction:

- A delete that another `deleting` listener cancels, or that fails, forgets nothing, so the identity never outlives its
  factors.
- A soft delete forgets nothing, so a restored identity still has its factors; a force delete forgets it.
- The forgetting commits on its own after the delete. Run the delete inside a transaction on the storage connection
  (`mfa.storage.connection`) to make the two one change; an identity stored on another connection cannot be, and a
  failure while forgetting it leaves records owned by an identity that no longer exists.
- A change already holding the identity's factor state lock commits first and is deleted with the rest.

An identity that is not an Eloquent model, or a model deleted without its events (a query builder `delete()`), is
forgotten by calling the helper:

```php
use SineMacula\Laravel\Mfa\Lifecycle\ForgetIdentity;

app(ForgetIdentity::class)->forget($identity);
```

The temporary attempt throttles are left to expire: they are keyed by a hash and hold nothing that names the identity.

## Identities that are not Eloquent models

An identity the guard builds from somewhere other than Eloquent implements the contract's methods itself, returning its
factors from the configured factor model, owned by its class name and its key:

```php
use SineMacula\Laravel\Mfa\Models\Factor;

public function authFactors(): Builder
{
    return Factor::query()
        ->where('authenticatable_type', static::class)
        ->where('authenticatable_id', (string) $this->getAuthIdentifier());
}
```
