<?php

declare(strict_types = 1);

use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Models\Factor;

return [

    /*
    |---------------------------------------------------------------------------
    | Applications
    |---------------------------------------------------------------------------
    |
    | Each application's settings, keyed by its name: the guard's name, unless
    | an application resolver says otherwise. Factors, recovery codes and
    | attempt state belong to the identity and are the same in every
    | application; an application only chooses what it accepts and offers.
    |
    | An application enables no factor type and requires no factor until it
    | says so, and one that is not listed here enables nothing. Every
    | configured application declares the first factor its guard signs people
    | in with, unless a first factor resolver is bound. Every key is checked
    | when the package boots, but no flow applies these blocks yet. See the
    | configuration guide for every key, its default, its bounds and whether
    | it is applied yet:
    |
    | 'web' => [
    |     'types'          => ['totp'],
    |     'requirement'    => 'enrolled',        // never, enrolled or always
    |     'recovery_codes' => ['enabled' => true, 'level' => 'aal2'],
    |     'bootstrap'      => ['enabled' => false, 'types' => []],
    |     'limits'         => ['confirmed_per_type' => 5, 'confirmed' => 10, 'pending' => 2],
    |     'totp_window'    => 1,
    |     'freshness'      => ['mfa.remove_factor' => 900],
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
    | The database connection every package table lives on, `null` for the
    | default connection. The shipped models read and write it, the shipped
    | migrations create their tables on it, and every change that depends on an
    | identity's whole factor state runs its transaction on it, so a configured
    | model on another connection is refused when the package boots. Changing
    | it moves no table: it is deployment configuration, fixed for the life of
    | a process.
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
    | The factor model and its table. The model must extend Eloquent's model
    | and implement the package's `EloquentFactor` contract; the shipped one
    | uses a ULID primary key and a polymorphic owner relation, and may be
    | subclassed or replaced.
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
    | The table holding one row per identity that owns factors. Every change
    | that depends on the identity's whole factor state locks its row first,
    | then the identity's factors, so two such changes for one identity run one
    | after the other.
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
    | The algorithm (sha1, sha256 or sha512), digits (6 to 8) and period (15 to
    | 120 seconds) new enrolments use, and the window (0 to 3 steps either side
    | of the current one) of an application that sets no window of its own.
    |
    */

    'totp' => [
        'algorithm' => env('MFA_TOTP_ALGORITHM', 'sha1'),
        'digits'    => env('MFA_TOTP_DIGITS', 6),
        'period'    => env('MFA_TOTP_PERIOD', 30),
        'window'    => env('MFA_TOTP_WINDOW', 1),
    ],

    /*
    |---------------------------------------------------------------------------
    | Delivered codes
    |---------------------------------------------------------------------------
    |
    | Codes sent by SMS or email: their digits (6 to 10), lifetime (1 to 10
    | minutes), the cooldown before another is sent (up to the lifetime), the
    | caps on how many one factor and one identity are sent within the send
    | window, the SMS message (which must carry `:code`) and the email message
    | class (`MfaCodeMessage` or a subclass).
    |
    */

    'codes' => [
        'length'                  => env('MFA_CODES_LENGTH', 6),
        'ttl_minutes'             => env('MFA_CODES_TTL_MINUTES', 10),
        'resend_cooldown_seconds' => env('MFA_CODES_RESEND_COOLDOWN_SECONDS', 60),
        'factor_send_limit'       => env('MFA_CODES_FACTOR_SEND_LIMIT', 5),
        'identity_send_limit'     => env('MFA_CODES_IDENTITY_SEND_LIMIT', 10),
        'send_window_minutes'     => env('MFA_CODES_SEND_WINDOW_MINUTES', 60),
        'sms_message'             => env('MFA_CODES_SMS_MESSAGE', 'Your verification code is: :code'),
        'mailable'                => MfaCodeMessage::class,
    ],

    /*
    |---------------------------------------------------------------------------
    | Recovery codes
    |---------------------------------------------------------------------------
    |
    | How many codes a set holds (1 to 50), each code's length (1 to 64) and
    | alphabet (no character repeated, ignoring case), which together must
    | give at least 40 bits of entropy once a code is normalised (case folded,
    | spaces and hyphens removed), and how few unused codes count as running
    | low (0 to the set's size).
    |
    */

    'recovery_codes' => [
        'count'     => env('MFA_RECOVERY_CODES_COUNT', 10),
        'length'    => env('MFA_RECOVERY_CODES_LENGTH', 12),
        'alphabet'  => env('MFA_RECOVERY_CODES_ALPHABET', '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'),
        'low_count' => env('MFA_RECOVERY_CODES_LOW_COUNT', 3),
    ],

    /*
    |---------------------------------------------------------------------------
    | Attempts
    |---------------------------------------------------------------------------
    |
    | How many failed attempts in a row lock a factor (1 to 20), how many
    | across an identity (1 to 100) and from one IP address (1 to 10000) within
    | the window (60 to 86400 seconds) lock or throttle them, how long a
    | lockout lasts (60 to 86400 seconds), and how many consecutive failures
    | disable a factor (1 to 100).
    |
    */

    'attempts' => [
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
    | How long a pending factor can be confirmed after its enrolment starts (1
    | to 60 minutes).
    |
    */

    'enrollment' => [
        'ttl_minutes' => env('MFA_ENROLLMENT_TTL_MINUTES', 15),
    ],

    /*
    |---------------------------------------------------------------------------
    | Proofs
    |---------------------------------------------------------------------------
    |
    | How long a recorded verification counts before the person must verify
    | again (0 to 525600 minutes). With 0 none counts, so the `mfa` middleware
    | refuses every request: use its step-up parameter to require a fresh
    | verification for one route group instead.
    |
    */

    'proofs' => [
        'max_age_minutes' => env('MFA_PROOFS_MAX_AGE_MINUTES', 20160),
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
];
