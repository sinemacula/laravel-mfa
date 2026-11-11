<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Mail\SendQueuedMailable;
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;

/**
 * Sensitive strings collected from one exception or log record before it is
 * redacted, so they can be redacted wherever else they appear.
 *
 * Known values (a delivery's code and destination) are redacted wherever they
 * occur. Collected values may be as short as a factor type, so they match only
 * whole strings unless they are six characters or more.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SensitiveValues
{
    /** @var int Shortest collected value redacted from within a longer string. */
    private const int CONTAINED_LENGTH = 6;

    /**
     * @param  list<string>  $known
     * @param  list<string>  $collected
     */
    private function __construct(

        /** Redacted from any string containing them. */
        private array $known,

        /** Redacted from a string equal to one, or containing one of six characters or more. */
        private array $collected,
    ) {}

    /**
     * @return self
     */
    public static function none(): self
    {
        return new self([], []);
    }

    /**
     * Redacted whatever their length; empty values and `null` are dropped.
     *
     * @param  ?string  ...$values
     * @return self
     */
    public static function known(#[\SensitiveParameter] ?string ...$values): self
    {
        return new self(self::usable($values), []);
    }

    /**
     * Every string when the frame touches the package, otherwise only sensitive
     * or secret-keyed strings and code messages.
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
     * As for a frame outside the package, plus what logged exceptions recorded.
     * Expects values already passed through `Redactor::normalize()`.
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
     * A `CodeMessage`, an `MfaCodeMessage` or a queued job sending one.
     *
     * @param  mixed  $value
     * @return bool
     */
    public static function isCodeMessage(mixed $value): bool
    {
        return self::codeMessageOf($value) !== null;
    }

    /**
     * The code and the destination or recipient addresses.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage|\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage  $message
     * @return list<string>
     */
    public static function ofCodeMessage(#[\SensitiveParameter] CodeMessage|MfaCodeMessage $message): array
    {
        if ($message instanceof CodeMessage) {
            return [$message->code->reveal(), $message->destination()];
        }

        $recipients = [...$message->to, ...$message->cc, ...$message->bcc];
        $addresses  = array_map(static fn (mixed $recipient): mixed => is_array($recipient) ? ($recipient['address'] ?? null) : null, $recipients);

        return [$message->code, ...array_values(array_filter($addresses, is_string(...)))];
    }

    /**
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
     * Whether the string is to be redacted whole.
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
     * The text with every redactable occurrence replaced by the marker.
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

        // strtr matches longest first and never rescans a marker it inserted
        return strtr($text, $replacements);
    }

    /**
     * Walks up to `Redactor::MAX_DEPTH` levels deep.
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
     * Everything under a key naming a secret, code or destination is collected.
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
     * @param  mixed  $value
     * @return \SineMacula\Laravel\Mfa\Codes\CodeMessage|\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage|null
     */
    private static function codeMessageOf(mixed $value): CodeMessage|MfaCodeMessage|null
    {
        return match (true) {
            $value instanceof CodeMessage, $value instanceof MfaCodeMessage                    => $value,
            $value instanceof SendQueuedMailable && $value->mailable instanceof MfaCodeMessage => $value->mailable,
            default                                                                            => null,
        };
    }

    /**
     * Unique values, without empty strings or the redaction marker.
     *
     * @param  array<array-key, ?string>  $values
     * @return list<string>
     */
    private static function usable(array $values): array
    {
        return array_values(array_unique(array_filter($values, static fn (?string $value): bool => $value !== null && $value !== '' && $value !== RevealedSecret::REDACTED)));
    }
}
