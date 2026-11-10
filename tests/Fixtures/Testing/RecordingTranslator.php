<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use Illuminate\Contracts\Translation\Translator;

/**
 * A translator that answers as the one it decorates and notes everything it is
 * given, to show a code never reaches it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingTranslator implements Translator
{
    /** @var list<mixed> Everything the translator was given. */
    public array $given = [];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Translation\Translator  $translator
     */
    public function __construct(

        /** The translator that answers. */
        private readonly Translator $translator,
    ) {}

    /**
     * Note the arguments and answer.
     *
     * @param  string  $key
     * @param  array<array-key, mixed>  $replace
     * @param  ?string  $locale
     * @return mixed
     */
    #[\Override]
    public function get(mixed $key, array $replace = [], mixed $locale = null): mixed
    {
        $this->given[] = [$key, $replace, $locale];

        return $this->translator->get($key, $replace, $locale);
    }

    /**
     * Note the arguments and answer.
     *
     * @param  string  $key
     * @param  array<array-key, mixed>|\Countable|float|int  $number
     * @param  array<array-key, mixed>  $replace
     * @param  ?string  $locale
     * @return string
     */
    #[\Override]
    public function choice(mixed $key, $number, array $replace = [], mixed $locale = null): string
    {
        $this->given[] = [$key, $number, $replace, $locale];

        return $this->translator->choice($key, $number, $replace, $locale);
    }

    /**
     * The decorated translator's locale.
     *
     * @return string
     */
    #[\Override]
    public function getLocale(): string
    {
        return $this->translator->getLocale();
    }

    /**
     * Set the decorated translator's locale.
     *
     * @param  string  $locale
     * @return void
     */
    #[\Override]
    public function setLocale(mixed $locale): void
    {
        $this->translator->setLocale($locale);
    }
}
