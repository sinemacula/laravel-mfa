<?php

declare(strict_types = 1);

namespace Tests\Feature\Localization;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Support\ConsumerMessages;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Testing\ChooseLocale;
use Tests\TestCase;

/**
 * The route gate's refusal in the words of the locale it is raised in: on a
 * JSON answer, which carries the message; on Laravel's stock HTML page, which
 * does not; and never in the challenge header, which is for a developer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InsufficientAuthenticationException::class)]
#[CoversClass(ConsumerMessages::class)]
final class RefusalWordingTest extends TestCase
{
    /** @var string The refusal in the shipped English. */
    private const string ENGLISH = 'Further authentication is required.';

    /** @var string The refusal in French, in characters a header may not quote. */
    private const string FRENCH = 'Une "authentification" supplémentaire est requise.';

    /**
     * Debug is off, as in production, and the refusal has a translation.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('app.debug', false);

        app('translator')->addLines(['messages.further_authentication_required' => self::FRENCH], 'fr', 'mfa');
    }

    /**
     * A JSON refusal in a locale a middleware chose through the kernel is in
     * that locale's words, with no challenge header.
     *
     * @return void
     */
    public function testAJsonRefusalIsInTheLocaleOfTheRequest(): void
    {
        $this->actingAs($this->person());

        $response = $this->getJson('wording/fr');

        $response->assertUnauthorized();
        $response->assertExactJson(['message' => self::FRENCH]);
        $response->assertHeaderMissing('WWW-Authenticate');
    }

    /**
     * Without a chosen locale the refusal is in the shipped English.
     *
     * @return void
     */
    public function testAJsonRefusalInTheDefaultLocaleIsEnglish(): void
    {
        $this->actingAs($this->person());

        $this->getJson('wording/default')->assertUnauthorized()->assertExactJson(['message' => self::ENGLISH]);
    }

    /**
     * A locale with no translation and a fallback with none says the English.
     *
     * @return void
     */
    public function testAJsonRefusalInAnUntranslatedLocaleIsEnglish(): void
    {
        app('translator')->setFallback('de');

        $this->actingAs($this->person());

        $this->getJson('wording/it')->assertUnauthorized()->assertExactJson(['message' => self::ENGLISH]);
    }

    /**
     * Laravel's stock HTML page says its own words and not the exception's, so
     * the translation does not appear there: it is the JSON answer that carries
     * it.
     *
     * @return void
     */
    public function testTheStockHtmlRefusalDoesNotCarryTheMessage(): void
    {
        $this->actingAs($this->person());

        $response = $this->get('wording/fr');

        $response->assertUnauthorized();
        $response->assertSee('Unauthorized');
        $response->assertDontSee(self::ENGLISH);
        $response->assertDontSee(self::FRENCH);
    }

    /**
     * The exception is worded in the locale when it is raised, so every raiser
     * gets it.
     *
     * @return void
     */
    public function testTheExceptionIsWordedWhenRaised(): void
    {
        $english = new InsufficientAuthenticationException(Requirement::none());

        app()->setLocale('fr');

        $french = new InsufficientAuthenticationException(Requirement::none());

        self::assertSame(self::ENGLISH, $english->getMessage());
        self::assertSame(self::FRENCH, $french->getMessage());
    }

    /**
     * Raising the refusal with no translator raises the refusal.
     *
     * @return void
     */
    public function testRaisingItWithoutATranslatorStillRaisesIt(): void
    {
        $container = Container::getInstance();

        Container::setInstance(new Container);

        try {
            self::assertSame(self::ENGLISH, (new InsufficientAuthenticationException(Requirement::none()))->getMessage());
        } finally {
            Container::setInstance($container);
        }
    }

    /**
     * The challenge header's description stays the shipped English, whatever
     * the locale's wording or an application's override of `en`, and all of it
     * is within RFC 6750's character set.
     *
     * @return void
     */
    public function testTheChallengeHeaderIsAlwaysTheShippedEnglish(): void
    {
        app('translator')->addLines(['messages.further_authentication_required' => 'An "override" of \ en.'], 'en', 'mfa');

        $overridden = new InsufficientAuthenticationException(Requirement::none());

        app()->setLocale('fr');

        $translated = new InsufficientAuthenticationException(Requirement::none());

        foreach ([$overridden, $translated] as $exception) {
            $header = $exception->wwwAuthenticate();

            self::assertSame('Bearer error="insufficient_user_authentication", error_description="' . self::ENGLISH . '"', $header);
        }

        // RFC 6750 section 3: %x20-21 / %x23-5B / %x5D-7E
        self::assertMatchesRegularExpression('/^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/D', self::ENGLISH);
    }

    /**
     * Define the routes the tests call: the gate, behind a middleware choosing
     * the locale as an application's own would, or with no choice at all.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->get('wording/default', static fn (): string => 'reached')->middleware('mfa:level=aal2');
        $router->get('wording/fr', static fn (): string => 'reached')->middleware([ChooseLocale::class . ':fr', 'mfa:level=aal2']);
        $router->get('wording/it', static fn (): string => 'reached')->middleware([ChooseLocale::class . ':it', 'mfa:level=aal2']);
    }

    /**
     * A person.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function person(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->create(['email' => 'person@example.test']);
    }
}
