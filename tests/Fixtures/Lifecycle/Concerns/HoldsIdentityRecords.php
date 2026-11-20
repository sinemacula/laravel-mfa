<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Lifecycle\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * Gives an identity a record in every table the package keeps by owner, and
 * counts them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait HoldsIdentityRecords
{
    /**
     * Keeps the identity's state row when it already has one.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     */
    protected function giveRecords(Authenticatable $identity): void
    {
        $owner = $this->ownerOf($identity);
        $now   = CarbonImmutable::now();

        $factor = Factor::query()->create([...$owner, 'type' => 'totp']);

        Enrollment::query()->create([
            ...$owner,
            'factor_id'   => $factor->id,
            'grant_hash'  => hash('sha256', $factor->id),
            'application' => 'web',
            'session_id'  => 'sign-in-digest',
            'generation'  => 0,
            'authority'   => EnrollmentAuthorization::STEP_UP,
            'expires_at'  => $now,
        ]);
        Code::query()->create([
            ...$owner,
            'factor_id'   => $factor->id,
            'purpose'     => 'sign_in',
            'application' => 'web',
            'code_hash'   => hash('sha256', 'c' . $factor->id),
            'sent_at'     => $now,
            'expires_at'  => $now,
        ]);
        RecoveryCode::query()->create([...$owner, 'code_hash' => 'hash', 'generation' => 1]);
        PasskeyAssociation::query()->create([
            ...$owner,
            'factor_id'          => $factor->id,
            'credential_id_hash' => hash('sha256', 'p' . $factor->id),
            'credential_id'      => 'credential',
        ]);
        IdentityState::query()->firstOrCreate($owner);
    }

    /**
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return array<string, int>
     */
    protected function recordCounts(Authenticatable $identity): array
    {
        $counts = [];

        foreach ($this->recordTables() as $table) {
            $counts[$table] = DB::table($table)->where($this->ownerOf($identity))->count();
        }

        return $counts;
    }

    /**
     * @param  int  $count
     * @return array<string, int>
     */
    protected function eachTableHolding(int $count): array
    {
        return array_fill_keys($this->recordTables(), $count);
    }

    /**
     * @return list<string>
     */
    private function recordTables(): array
    {
        return array_map(TableNames::of(...), [
            TableNames::FACTORS,
            TableNames::ENROLLMENTS,
            TableNames::CODES,
            TableNames::RECOVERY_CODES,
            TableNames::PASSKEY_ASSOCIATIONS,
            TableNames::IDENTITY_STATES,
        ]);
    }

    /**
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return array{authenticatable_type: string, authenticatable_id: string}
     */
    private function ownerOf(Authenticatable $identity): array
    {
        /** @var int|string $key */
        $key = $identity->getAuthIdentifier();

        return ['authenticatable_type' => IdentityType::of($identity), 'authenticatable_id' => (string) $key];
    }
}
