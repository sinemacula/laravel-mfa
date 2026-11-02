<?php

declare(strict_types = 1);

return [

    /*
    |---------------------------------------------------------------------------
    | Consumer messages
    |---------------------------------------------------------------------------
    |
    | Everything the package can put in front of a consumer. The keys and their
    | placeholders are stable names. A code line must keep the exact `:code`
    | placeholder or the shipped English is sent instead. Every line is plain
    | text: the email escapes it, so markup shows as written. See the
    | localisation guide.
    |
    */

    'further_authentication_required' => 'Further authentication is required.',
    'sms_code'                        => 'Your verification code is: :code',
    'email_subject'                   => 'Your verification code',
    'email_code'                      => 'Your verification code is: :code',
    'email_expiry'                    => 'This code expires in :minutes minute.|This code expires in :minutes minutes.',
    'email_ignore'                    => 'If you did not request this code, you can safely ignore this message.',

];
