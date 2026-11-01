<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Mail\SendQueuedMailable;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;

/**
 * The strings known to be sensitive for one scrub of an exception or one log
 * record, collected before either is redacted, so they can be redacted wherever
 * else they appear: in another frame's arguments, in an exception's message or
 * in a log record's message.
 *
 * They come in two kinds. A value known to be sensitive, because it was given
 * explicitly (the code and the destination of a delivery) or read from a code
 * message (its code and its recipients' addresses), is redacted from any string
 * that contains it, whatever its length. A value collected from a trace's
 * arguments or a log's values (a string a frame of the package received, a
 * value marked as sensitive, a value under a key naming a secret, a code or a
 * destination) may be as short and as common as a factor type, so a string is
 * redacted for it only when it is the value, or when the value is six
 * characters or more and the string contains it.
 *
 * Nothing is kept beyond the value: each scrub and each record collects its
 * own, so what one delivery or one queued job collected never reaches another.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SensitiveValues
{
    /** @var int The length from which a collected value is redacted wherever a string contains it. */
    private const int CONTAINED_LENGTH = 6;

    /**
     * Constructor.
     *
     * @param  list<string>  $known
     * @param  list<string>  $collected
     */
    private function __construct(

        /** The values redacted from any string containing them. */
        private array $known,

        /** The values redacted from a string that is one, or contains one of six characters or more. */
        private array $collected,
    ) {}

    /**
     * No values.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self([], []);
    }

    /**
     * The values given, known to be sensitive whatever their length. Empty
     * values and `null` are left out.
     *
     * @param  ?string  ...$values
     * @return self
     */
    public static function known(#[\SensitiveParameter] ?string ...$values): self
    {
        return new self(self::usable($values), []);
    }

    /**
     * The values in a trace frame's arguments: every string, when the frame
     * touches the package, and otherwise the strings a sensitive value holds or
     * a key naming a secret, a code or a destination keys; and the code and the
     * recipients of a code message, as known.
     *
     * @param  array<array-key, mixed>  $arguments
     * @param  bool  $all
     * @return self
     */
    public static function inArguments(array $arguments, bool $all): self
    {
        $values = self::walk($arguments, $all, false, 0);

        return new self(self::usable($values->known), self::usable($values->collected));
    }

    /**
     * The values in a log's values, as in a trace frame's arguments that do not
     * touch the package, and those an exception among them recorded in its
     * trace and the traces of its previous ones (see `ExceptionScrubber`). The
     * values are read as `Redactor::normalise()` gives them, so an object's
     * form, which the redaction reaches, is read too; any other object is not.
     *
     * @param  array<array-key, mixed>  $values
     * @return self
     */
    public static function inLogValues(array $values): self
    {
        $found = self::walk($values, false, true, 0);

        return new self(self::usable($found->known), self::usable($found->collected));
    }

    /**
     * Whether the value is a code message, or a queued job sending one, which
     * carries the code in clear.
     *
     * @param  mixed  $value
     * @return bool
     */
    public static function isCodeMessage(mixed $value): bool
    {
        return self::codeMessageOf($value) !== null;
    }

    /**
     * The code a code message carries, and the address of each of its
     * recipients.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\MfaCodeMessage  $message
     * @return list<string>
     */
    public static function ofCodeMessage(#[\SensitiveParameter] MfaCodeMessage $message): array
    {
        $recipients = [...$message->to, ...$message->cc, ...$message->bcc];
        $addresses  = array_map(static fn (mixed $recipient): mixed => is_array($recipient) ? ($recipient['address'] ?? null) : null, $recipients);

        return [$message->code, ...array_values(array_filter($addresses, is_string(...)))];
    }

    /**
     * These values and the other's.
     *
     * @param  self  $other
     * @return self
     */
    public function with(self $other): self
    {
        return new self(
            array_values(array_unique([...$this->known, ...$other->known])),
            array_values(array_unique([...$this->collected, ...$other->collected])),
        );
    }

    /**
     * Whether the string is to be redacted whole: it contains a value known to
     * be sensitive, is a value collected, or contains one of six characters or
     * more.
     *
     * @param  string  $value
     * @return bool
     */
    public function matches(string $value): bool
    {
        foreach ($this->known as $known) {
            if (str_contains($value, $known)) {
                return true;
            }
        }

        foreach ($this->collected as $collected) {
            if ($value === $collected || (strlen($collected) >= self::CONTAINED_LENGTH && str_contains($value, $collected))) {
                return true;
            }
        }

        return false;
    }

    /**
     * The text, such as an exception's or a log record's message, with every
     * occurrence of a value replaced by `[redacted]`: of every value known to
     * be sensitive, and of every value collected of six characters or more. A
     * text that is a value collected becomes `[redacted]`.
     *
     * @param  string  $text
     * @return string
     */
    public function redactIn(string $text): string
    {
        $replacements = [];

        foreach ([...$this->known, ...$this->collected] as $value) {
            if (!in_array($value, $this->known, true) && strlen($value) < self::CONTAINED_LENGTH && $value !== $text) {
                continue;
            }

            $replacements[$value] = RevealedSecret::REDACTED;
        }

        // Each occurrence is replaced once, longest value first, and a marker
        // already put in is never searched again
        return strtr($text, $replacements);
    }

    /**
     * The sensitive values in the value, up to ten levels deep, each as often
     * as it was found.
     *
     * @param  mixed  $value
     * @param  bool  $all
     * @param  bool  $log
     * @param  int  $depth
     * @return self
     */
    private static function walk(mixed $value, bool $all, bool $log, int $depth): self
    {
        if ($depth > Redactor::MAX_DEPTH) {
            return self::none();
        }

        $message = self::codeMessageOf($value);

        return match (true) {
            $message !== null                          => new self(self::ofCodeMessage($message), []),
            $value instanceof \SensitiveParameterValue => self::walk($value->getValue(), true, $log, $depth + 1),
            $value instanceof RevealedSecret           => self::walk($value->reveal(), true, $log, $depth + 1),
            $log && $value instanceof \Throwable       => ExceptionScrubber::sensitiveValuesOf($value),
            is_string($value)                          => new self([], $all ? [$value] : []),
            is_array($value)                           => self::walkEach($value, $all, $log, $depth),
            default                                    => self::none(),
        };
    }

    /**
     * The sensitive values in each item of the array, those under a key naming
     * a secret, a code or a destination all collected.
     *
     * @param  array<array-key, mixed>  $values
     * @param  bool  $all
     * @param  bool  $log
     * @param  int  $depth
     * @return self
     */
    private static function walkEach(array $values, bool $all, bool $log, int $depth): self
    {
        $known     = [];
        $collected = [];

        foreach ($values as $key => $value) {
            $found = self::walk($value, $all || (is_string($key) && Redactor::namesASecret($key)), $log, $depth + 1);

            array_push($known, ...$found->known);
            array_push($collected, ...$found->collected);
        }

        return new self($known, $collected);
    }

    /**
     * The code message the value is, or the queued job sends.
     *
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage
     */
    private static function codeMessageOf(mixed $value): ?MfaCodeMessage
    {
        return match (true) {
            $value instanceof MfaCodeMessage                                                   => $value,
            $value instanceof SendQueuedMailable && $value->mailable instanceof MfaCodeMessage => $value->mailable,
            default                                                                            => null,
        };
    }

    /**
     * The values worth redacting elsewhere, each once: neither an empty string
     * nor the redaction marker.
     *
     * @param  array<array-key, ?string>  $values
     * @return list<string>
     */
    private static function usable(array $values): array
    {
        return array_values(array_unique(array_filter($values, static fn (?string $value): bool => $value !== null && $value !== '' && $value !== RevealedSecret::REDACTED)));
    }
}
