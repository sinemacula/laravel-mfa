<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Concerns;

use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Date;

/**
 * Writes and reads the model's times in UTC whatever the application timezone,
 * as the columns hold no offset and a daylight saving change would put
 * wall-clock times out of order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait StoresTimesInUtc
{
    /**
     * In UTC, so `fromDateTime()` formats it for the column as UTC; a string
     * without an offset is a UTC time.
     *
     * @param  mixed  $value
     * @return \Illuminate\Support\Carbon
     */
    protected function asDateTime(mixed $value): CarbonInterface
    {
        if (!is_string($value) || is_numeric($value)) {
            return parent::asDateTime($value)->utc();
        }

        try {
            $time = Carbon::createFromFormat($this->getDateFormat(), $value, 'UTC');
        } catch (\InvalidArgumentException) {
            $time = null;
        }

        return Date::instance($time ?? Date::parse($value, 'UTC'))->utc();
    }
}
