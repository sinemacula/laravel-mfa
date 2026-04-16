<?php

declare(strict_types = 1);

use SineMacula\Laravel\Mfa\Models\Factor;

return [

    /*
    |---------------------------------------------------------------------------
    | Factor model
    |---------------------------------------------------------------------------
    |
    | Configures the package's default Eloquent factor adapter. The `model` key
    | must resolve to a class implementing the package's `Factor` contract; the
    | shipped default uses a ULID primary key and a polymorphic
    | `authenticatable` relation. Consumers may subclass the shipped model or
    | swap it entirely via this binding.
    |
    */

    'factor' => [
        'model' => env('MFA_FACTOR_MODEL', Factor::class),
        'table' => env('MFA_FACTOR_TABLE', 'mfa_factors'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Default expiry
    |---------------------------------------------------------------------------
    |
    | The number of minutes an MFA verification remains valid before the user
    | must re-verify. Individual drivers may override this value via their own
    | `expiry` setting. Setting this to `0` makes every prior verification
    | "expired" — the route-level `RequireMfa` middleware will reject every
    | request, so use the step-up middleware variant when you need to require
    | re-verification for a specific action without locking the user out
    | globally.
    |
    */

    'default_expiry' => (int) env('MFA_DEFAULT_EXPIRY_MINUTES', 20160),

    /*
    |---------------------------------------------------------------------------
    | Cache prefix
    |---------------------------------------------------------------------------
    |
    | Prefix used for the runtime request-scoped MFA state cache. This is an
    | in-memory cache that avoids redundant database queries within a single
    | request lifecycle.
    |
    */

    'cache_prefix' => env('MFA_CACHE_PREFIX', 'mfa:'),

    /*
    |---------------------------------------------------------------------------
    | Drivers
    |---------------------------------------------------------------------------
    |
    | Per-driver configuration. Each key corresponds to a driver name
    | registered with the MFA manager.
    |
    */

    'drivers' => [

        'totp' => [
            'window' => (int) env('MFA_TOTP_WINDOW', 1),
        ],

        'email' => [
            'code_length'  => (int) env('MFA_EMAIL_CODE_LENGTH', 6),
            'expiry'       => (int) env('MFA_EMAIL_EXPIRY_MINUTES', 10),
            'max_attempts' => (int) env('MFA_EMAIL_MAX_ATTEMPTS', 3),

            // Optional alphabet override. `null` keeps the default
            // numeric code; supply a non-empty string of two or more
            // characters to draw from a custom set (Crockford base32,
            // hex, alphabetic for voice delivery, etc.).
            'alphabet' => env('MFA_EMAIL_ALPHABET'),
        ],

        'sms' => [
            'code_length'      => (int) env('MFA_SMS_CODE_LENGTH', 6),
            'expiry'           => (int) env('MFA_SMS_EXPIRY_MINUTES', 10),
            'max_attempts'     => (int) env('MFA_SMS_MAX_ATTEMPTS', 3),
            'message_template' => env(
                'MFA_SMS_MESSAGE_TEMPLATE',
                'Your verification code is: :code',
            ),

            // See email.alphabet above. SMS deliveries often benefit
            // from an unambiguous Crockford-base32 set, e.g.
            // '0123456789ABCDEFGHJKMNPQRSTVWXYZ'.
            'alphabet' => env('MFA_SMS_ALPHABET'),
        ],

        'backup_code' => [
            'code_length' => (int) env('MFA_BACKUP_CODE_LENGTH', 10),
            'alphabet'    => env(
                'MFA_BACKUP_CODE_ALPHABET',
                '23456789ABCDEFGHJKLMNPQRSTUVWXYZ',
            ),
            'code_count' => (int) env('MFA_BACKUP_CODE_COUNT', 10),
        ],

    ],

    /*
    |---------------------------------------------------------------------------
    | Lockout
    |---------------------------------------------------------------------------
    |
    | How long, in minutes, a factor is locked from further verification
    | attempts after reaching its per-driver `max_attempts` threshold. The
    | lockout clears automatically once the window passes; administrative
    | unlocks are a consumer-side concern.
    |
    */

    'lockout_minutes' => (int) env('MFA_LOCKOUT_MINUTES', 15),
];
