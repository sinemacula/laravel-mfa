<?php

declare(strict_types = 1);

use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;

return [

    /*
    |---------------------------------------------------------------------------
    | Applications
    |---------------------------------------------------------------------------
    |
    | Each application's settings, keyed by name (the guard's name unless an
    | application resolver says otherwise). Factors belong to the identity; an
    | application only chooses what it accepts and offers.
    |
    | An unlisted application enables nothing. Each must declare its
    | `first_factor` unless a first factor resolver is bound. `freshness` maps
    | an operation to seconds or to a requirement whose every part has a
    | `max_age`. See the configuration guide for defaults and bounds:
    |
    | 'web' => [
    |     'types'          => ['totp'],
    |     'requirement'    => 'enrolled',        // never, enrolled or always
    |     'recovery_codes' => ['enabled' => true, 'level' => 'aal2'],
    |     'bootstrap'      => ['enabled' => false, 'types' => []],
    |     'limits'         => ['confirmed_per_type' => 5, 'confirmed' => 10, 'pending' => 2],
    |     'totp_window'    => 1,
    |     'freshness'      => [
    |         'mfa.remove_factor'   => 900,
    |         'billing.change_plan' => ['minimum_level' => ['level' => 'aal2', 'max_age' => 600]],
    |     ],
    |     'first_factor'   => ['method' => 'password', 'channel' => 'password'],
    | ],
    |
    */

    'applications' => [],

    /*
    |---------------------------------------------------------------------------
    | Storage
    |---------------------------------------------------------------------------
    |
    | The connection every package table lives on, `null` for the default.
    | Changing it moves no table, and it must stay fixed for a process's life.
    |
    */

    'storage' => [
        'connection' => env('MFA_STORAGE_CONNECTION'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Factor model
    |---------------------------------------------------------------------------
    |
    | The factor model, an Eloquent model implementing `EloquentFactor`, and
    | its table. No two package tables may share a name.
    |
    */

    'factor' => [
        'model' => env('MFA_FACTOR_MODEL', Factor::class),
        'table' => env('MFA_FACTOR_TABLE', 'mfa_factors'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Identity state
    |---------------------------------------------------------------------------
    |
    | The table holding one row of factor state per identity, also used as its
    | lock.
    |
    */

    'identity_state' => [
        'table' => env('MFA_IDENTITY_STATE_TABLE', 'mfa_identity_states'),
    ],

    /*
    |---------------------------------------------------------------------------
    | TOTP
    |---------------------------------------------------------------------------
    |
    | New enrolments' algorithm (sha1, sha256 or sha512), digits (6 to 8) and
    | period (15 to 120 seconds); the default window (0 to 3 steps either side);
    | and the issuer an authenticator app shows (`app.name` when unset).
    |
    */

    'totp' => [
        'algorithm' => env('MFA_TOTP_ALGORITHM', 'sha1'),
        'digits'    => env('MFA_TOTP_DIGITS', 6),
        'period'    => env('MFA_TOTP_PERIOD', 30),
        'window'    => env('MFA_TOTP_WINDOW', 1),
        'issuer'    => env('MFA_TOTP_ISSUER'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Delivered codes
    |---------------------------------------------------------------------------
    |
    | Codes sent by SMS or email: digits (6 to 10), lifetime (1 to 10 minutes),
    | attempts per challenge (1 to 10), how long resends may run (the lifetime
    | to 60 minutes), the resend cooldown (up to the lifetime), per-destination
    | and per-identity send caps within the send window, and the email message
    | class. Enabling `sms` or `email` needs a bound `SmsSender` or
    | `EmailSender`. Wording is translated: see the localisation guide.
    |
    */

    'codes' => [
        'table'                   => env('MFA_CODES_TABLE', 'mfa_codes'),
        'length'                  => env('MFA_CODES_LENGTH', 6),
        'ttl_minutes'             => env('MFA_CODES_TTL_MINUTES', 10),
        'max_attempts'            => env('MFA_CODES_MAX_ATTEMPTS', 5),
        'challenge_ttl_minutes'   => env('MFA_CODES_CHALLENGE_TTL_MINUTES', 30),
        'resend_cooldown_seconds' => env('MFA_CODES_RESEND_COOLDOWN_SECONDS', 60),
        'factor_send_limit'       => env('MFA_CODES_FACTOR_SEND_LIMIT', 5),
        'identity_send_limit'     => env('MFA_CODES_IDENTITY_SEND_LIMIT', 10),
        'send_window_minutes'     => env('MFA_CODES_SEND_WINDOW_MINUTES', 60),
        'mailable'                => MfaCodeMessage::class,
    ],

    /*
    |---------------------------------------------------------------------------
    | Recovery codes
    |---------------------------------------------------------------------------
    |
    | The model (implementing `RecoveryCode`) and table; codes per set (1 to
    | 50); each code's length (1 to 64) and alphabet (no repeats, ignoring
    | case), together giving at least 40 bits of entropy; and the unused count
    | (0 to the set's size) at which `RecoveryCodesLow` is dispatched.
    |
    */

    'recovery_codes' => [
        'model'     => env('MFA_RECOVERY_CODES_MODEL', RecoveryCode::class),
        'table'     => env('MFA_RECOVERY_CODES_TABLE', 'mfa_recovery_codes'),
        'count'     => env('MFA_RECOVERY_CODES_COUNT', 10),
        'length'    => env('MFA_RECOVERY_CODES_LENGTH', 13),
        'alphabet'  => env('MFA_RECOVERY_CODES_ALPHABET', '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'),
        'low_count' => env('MFA_RECOVERY_CODES_LOW_COUNT', 3),
    ],

    /*
    |---------------------------------------------------------------------------
    | Attempts
    |---------------------------------------------------------------------------
    |
    | Failures in a row that lock a factor (1 to 20); failures per identity (1
    | to 100) and per IP (1 to 10000) within the window (60 to 86400 seconds);
    | lockout length (60 to 86400 seconds); and consecutive failures that
    | disable a factor (1 to 100). Only a success resets a factor's failures.
    |
    */

    'attempts' => [
        'table'           => env('MFA_ATTEMPTS_TABLE', 'mfa_attempts'),
        'factor_limit'    => env('MFA_ATTEMPTS_FACTOR_LIMIT', 5),
        'identity_limit'  => env('MFA_ATTEMPTS_IDENTITY_LIMIT', 20),
        'ip_limit'        => env('MFA_ATTEMPTS_IP_LIMIT', 100),
        'window_seconds'  => env('MFA_ATTEMPTS_WINDOW_SECONDS', 900),
        'lockout_seconds' => env('MFA_ATTEMPTS_LOCKOUT_SECONDS', 900),
        'failure_ceiling' => env('MFA_ATTEMPTS_FAILURE_CEILING', 100),
    ],

    /*
    |---------------------------------------------------------------------------
    | Enrolment
    |---------------------------------------------------------------------------
    |
    | How long a pending factor may be confirmed (1 to 60 minutes, shortened
    | by the freshness that authorised it) and how many wrong codes abandon it
    | (1 to 10).
    |
    */

    'enrollment' => [
        'table'        => env('MFA_ENROLLMENT_TABLE', 'mfa_enrollments'),
        'ttl_minutes'  => env('MFA_ENROLLMENT_TTL_MINUTES', 15),
        'max_attempts' => env('MFA_ENROLLMENT_MAX_ATTEMPTS', 5),
    ],

    /*
    |---------------------------------------------------------------------------
    | Passkeys
    |---------------------------------------------------------------------------
    |
    | The table associating passkeys with factors. The credentials belong to
    | the authentication layer.
    |
    */

    'passkeys' => [
        'table' => env('MFA_PASSKEYS_TABLE', 'mfa_passkey_associations'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Lifecycle
    |---------------------------------------------------------------------------
    |
    | How many days pruning keeps abandoned enrolments, expired codes and used
    | or replaced recovery codes (1 to 3650).
    |
    */

    'lifecycle' => [
        'prune_after_days' => env('MFA_LIFECYCLE_PRUNE_AFTER_DAYS', 30),
    ],

    /*
    |---------------------------------------------------------------------------
    | Secrets
    |---------------------------------------------------------------------------
    |
    | Whether secrets, codes and full destinations are redacted from logs and
    | reported exceptions. Only a value that reads as false turns it off.
    |
    */

    'secrets' => [
        'redact' => env('MFA_SECRETS_REDACT', true),
    ],
];
