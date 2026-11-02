<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Holds the package's namespaces to the dependency rules its design states:
 * which classes may not name which others. Each rule is data in `RULES`, so a
 * change that moves a class or narrows a dependency adds or tightens a rule
 * there. A rule applies to the classes in its `from` namespaces or classes (`*`
 * for every class of the package) except those in `except`, and forbids them to
 * name anything in its `forbids` namespaces or classes (`*` for the whole
 * package) except what `allows` lists; every name is relative to the package.
 *
 * A class names another through an import (`use`, grouped or aliased), a
 * qualified or fully qualified name in its code, or a fully qualified type in a
 * docblock. Names resolve as PHP resolves them, without regard to case, and a
 * qualified name only through a class or namespace import. The source is
 * tokenised, not parsed, so a name built at run time (a class name in a string,
 * say) and an unqualified name of a class in the same namespace are not seen:
 * the test is a backstop for the rules, not a proof of them.
 *
 * Two rules are about suffixes and calls rather than namespaces: only the
 * service provider names a capability's bindings class, so the provider is the
 * one composition root; and only the event dispatcher reaches Laravel's, so
 * every event the package dispatches goes through it, after the storage commit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class NamespaceDependenciesTest extends TestCase
{
    /** @var string The namespace every name below is relative to. */
    private const string PACKAGE = 'SineMacula\Laravel\Mfa\\';

    /** @var string A fully qualified name in a docblock. */
    private const string DOCBLOCK_NAME = '/(?<![A-Za-z0-9_\\\])\\\((?:[A-Za-z_][A-Za-z0-9_]*\\\)*[A-Za-z_][A-Za-z0-9_]*)/';

    /** @var list<string> Laravel's event dispatcher, by each name a class could reach it through. */
    private const array DISPATCHERS = [
        'Illuminate\Contracts\Events\Dispatcher',
        'Illuminate\Events\Dispatcher',
        'Illuminate\Support\Facades\Event',
        'Illuminate\Foundation\Events\Dispatchable',
    ];

    /** @var string The key Laravel's container binds its event dispatcher to. */
    private const string DISPATCHER_KEY = 'events';

    /** @var array<string, string> The classes that may reach Laravel's dispatcher, each with its reason. */
    private const array DISPATCHER_EXEMPTIONS = [
        'Events\EventDispatcher' => 'the one way the package dispatches an event',
        'Proofs\ProofBindings'   => 'registers listeners for Laravel\'s Login, Logout and CurrentDeviceLogout events and dispatches nothing',
    ];

    /** @var array<string, array{from: non-empty-list<string>, except: list<string>, forbids: non-empty-list<string>, allows: list<string>}> The rules, by what each holds. */
    private const array RULES = [
        'enums name nothing else of the package' => [
            'from'    => ['Enums'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => ['Enums'],
        ],
        'models name nothing of the package but its concerns, contracts, storage and enums' => [
            'from'    => ['Models'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => ['Models', 'Concerns', 'Contracts', 'Database', 'Enums'],
        ],
        'the seam defaults name nothing of the package but its contracts and enums' => [
            'from'    => ['Seams'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => ['Seams', 'Contracts', 'Enums'],
        ],
        'exceptions name nothing of the package but enums, the support helpers and the summaries and results they carry' => [
            'from'    => ['Exceptions'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => ['Exceptions', 'Enums', 'Support', 'Factors\FactorSummary', 'Codes\SendResult', 'Requirements\Requirement'],
        ],
        'events name nothing of the package but its context, contracts, storage, enums, support helpers and the factor summary' => [
            'from'    => ['Events'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => ['Events', 'Context', 'Contracts', 'Database', 'Enums', 'Support', 'Factors\FactorSummary'],
        ],
        'the assurance vocabulary names nothing of the capabilities that use it' => [
            'from'    => ['Assurance'],
            'except'  => [],
            'forbids' => [
                'Applications', 'Attempts', 'Codes', 'Config', 'Context', 'Database', 'Drivers', 'Enrollment', 'Events',
                'Factors', 'Http', 'Lifecycle', 'Models', 'Passkeys', 'RecoveryCodes', 'Seams', 'Verification',
                'Console', 'Testing', 'Facades',
            ],
            'allows' => [],
        ],
        'storage, the support helpers and secrets name no capability but the proof owner and the code message' => [
            'from'    => ['Database', 'Support', 'Secrets'],
            'except'  => [],
            'forbids' => [
                'Applications', 'Assurance', 'Attempts', 'Codes', 'Config', 'Context', 'Drivers', 'Enrollment', 'Events',
                'Factors', 'Http', 'Lifecycle', 'Passkeys', 'Proofs', 'RecoveryCodes', 'Requirements', 'Verification',
                'Console', 'Testing', 'Facades', 'Seams', 'MfaManager', 'MfaServiceProvider',
            ],
            'allows' => ['Proofs\ProofOwner', 'Codes\MfaCodeMessage'],
        ],
        'contracts name no model, capability service, seam default or composition root' => [
            'from'    => ['Contracts'],
            'except'  => [],
            'forbids' => [
                'Models', 'Lifecycle', 'Http', 'Console', 'Testing', 'Facades', 'Seams', 'MfaManager',
                'MfaServiceProvider', 'Attempts\AttemptService', 'Proofs\ProofService',
                'Requirements\RequirementService', 'RecoveryCodes\RecoveryCodeService',
                'Enrollment\EnrollmentService', 'Factors\FactorService', 'Verification\VerificationService',
                'Lifecycle\LifecycleService',
            ],
            'allows' => [],
        ],
        'only the manager names a flow service' => [
            'from'    => ['*'],
            'except'  => ['MfaManager'],
            'forbids' => ['Enrollment\EnrollmentService', 'Factors\FactorService', 'Lifecycle\LifecycleService', 'Verification\VerificationService'],
            'allows'  => [],
        ],
        'only the provider and the HTTP layer name the HTTP layer' => [
            'from'    => ['*'],
            'except'  => ['MfaServiceProvider', 'Http'],
            'forbids' => ['Http'],
            'allows'  => [],
        ],
        'only the provider, the configuration bindings and the console name the console' => [
            'from'    => ['*'],
            'except'  => ['MfaServiceProvider', 'Config\ConfigurationBindings', 'Console'],
            'forbids' => ['Console'],
            'allows'  => [],
        ],
        'only the provider, the facade and the driver bindings name the manager' => [
            'from'    => ['*'],
            'except'  => ['MfaServiceProvider', 'Facades\Mfa', 'Drivers\DriverBindings'],
            'forbids' => ['MfaManager'],
            'allows'  => [],
        ],
        'nothing names the provider or the facade' => [
            'from'    => ['*'],
            'except'  => [],
            'forbids' => ['MfaServiceProvider', 'Facades'],
            'allows'  => [],
        ],
        'only the testing helpers name the testing helpers' => [
            'from'    => ['*'],
            'except'  => ['Testing'],
            'forbids' => ['Testing'],
            'allows'  => [],
        ],
    ];

    /** @var ?array<string, list<string>> Every class of the package and every name it names, read once. */
    private static ?array $names = null;

    /** @var ?array<string, string> Every class of the package and its source, read once. */
    private static ?array $sources = null;

    /**
     * Rows of `[from, except, forbids, allows]`: each rule.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>, 2: list<string>, 3: list<string>}>
     */
    public static function provideRules(): iterable
    {
        foreach (self::RULES as $rule => $scope) {
            yield $rule => [$scope['from'], $scope['except'], $scope['forbids'], $scope['allows']];
        }
    }

    /**
     * No class a rule applies to names anything it forbids.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testNoClassNamesWhatItsRuleForbids(array $from, array $except, array $forbids, array $allows): void
    {
        self::assertSame([], self::violations(self::packageNames(), $from, $except, $forbids, $allows));
    }

    /**
     * Every namespace or class a rule names has a class in it, so a rule left
     * behind by a move fails rather than holding over nothing.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testEveryNameARuleGivesExists(array $from, array $except, array $forbids, array $allows): void
    {
        $classes = array_keys(self::sources());

        foreach ([...$from, ...$except, ...$forbids, ...$allows] as $named) {
            self::assertNotSame([], array_filter($classes, static fn (string $class): bool => self::isWithin($class, [$named])), "No class of the package is in {$named}.");
        }
    }

    /**
     * Only the service provider names a capability's bindings class, a package
     * class whose name ends in `Bindings`, so the provider is the one place the
     * package is composed; the suffix, not a list, decides, so a new
     * capability's bindings class is held without a change here.
     *
     * @return void
     */
    public function testOnlyTheProviderNamesABindingsClass(): void
    {
        $named = [];

        foreach (self::packageNames() as $class => $names) {

            if ($class === 'MfaServiceProvider') {
                continue;
            }

            foreach ($names as $name) {

                if (!str_ends_with(strtolower($name), 'bindings')) {
                    continue;
                }

                $named[] = "{$class} names {$name}";
            }
        }

        self::assertSame([], $named);
    }

    /**
     * Only the event dispatcher reaches Laravel's: outside the exempted
     * classes, none names Laravel's dispatcher, by its contract, its class, its
     * facade or the `Dispatchable` trait, resolves it by its container key, or
     * calls the `event()` helper, so every event the package dispatches goes
     * through `Events\EventDispatcher`.
     *
     * @return void
     */
    public function testOnlyTheEventDispatcherReachesLaravelsDispatcher(): void
    {
        $reaches = [];

        foreach (self::sources() as $class => $source) {

            if (array_key_exists($class, self::DISPATCHER_EXEMPTIONS)) {
                continue;
            }

            foreach (self::dispatchersIn($source) as $dispatcher) {
                $reaches[] = "{$class} reaches {$dispatcher}";
            }
        }

        self::assertSame([], $reaches);
    }

    /**
     * Each class exempted from the dispatcher rule exists and reaches Laravel's
     * dispatcher, so an exemption left behind by a change fails rather than
     * excusing nothing.
     *
     * @return void
     */
    public function testEveryDispatcherExemptionIsUsed(): void
    {
        foreach (array_keys(self::DISPATCHER_EXEMPTIONS) as $class) {
            self::assertNotSame([], self::dispatchersIn(self::sources()[$class] ?? ''), "{$class} is exempted but does not reach Laravel's dispatcher.");
        }
    }

    /**
     * Rows of `[code, reaches]`: a way of reaching Laravel's dispatcher, or of
     * not reaching it, and what the scanner finds in it.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideDispatcherReaches(): iterable
    {
        yield 'the contract imported under an alias' => ['use Illuminate\Contracts\Events\Dispatcher as Events;', ['Illuminate\Contracts\Events\Dispatcher']];
        yield 'the contract imported within a group' => ['use Illuminate\Contracts\{Events\Dispatcher, Foundation\Application};', ['Illuminate\Contracts\Events\Dispatcher']];
        yield 'the facade imported' => ['use Illuminate\Support\Facades\Event;', ['Illuminate\Support\Facades\Event']];
        yield 'the class fully qualified in code' => ['$events = new \Illuminate\Events\Dispatcher;', ['Illuminate\Events\Dispatcher']];
        yield 'the contract fully qualified in a docblock' => ['/** @var \Illuminate\Contracts\Events\Dispatcher $events */', ['Illuminate\Contracts\Events\Dispatcher']];
        yield 'the class named in another case' => ['$events = new \illuminate\events\DISPATCHER;', ['Illuminate\Events\Dispatcher']];
        yield 'the trait imported and used' => [
            "use Illuminate\\Foundation\\Events\\Dispatchable;\n\nfinal class Example\n{\n    use Dispatchable;\n}",
            ['Illuminate\Foundation\Events\Dispatchable'],
        ];
        yield 'the container key resolved' => ['$events = $this->container->make(\'events\');', ['\'events\'']];
        yield 'the container key resolved through the helper' => ['$events = app("events");', ['\'events\'']];
        yield 'another string' => ['$key = \'event\';', []];
        yield 'the helper called' => ['event(new Example);', ['event()']];
        yield 'the helper called fully qualified' => ['\event(new Example);', ['event()']];
        yield 'the helper called in another case' => ['Event(new Example);', ['event()']];
        yield 'a method named event called' => ['$this->event();', []];
        yield 'a method named event called null-safely' => ['$this?->event();', []];
        yield 'a static method named event called' => ['self::event();', []];
        yield 'a function named event declared' => ['function event(): void {}', []];
        yield 'another contract of Laravel\'s events imported' => ['use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;', []];
    }

    /**
     * The scanner finds Laravel's dispatcher however a class reaches it:
     * imported alone, aliased or grouped, through its facade or the
     * `Dispatchable` trait, fully qualified in code or in a docblock, by its
     * container key in either quotes, or by a call of the `event()` helper,
     * unqualified or fully qualified; and nothing for a method named `event`,
     * called or declared, another string, or another name of Laravel's events.
     *
     * @param  string  $code
     * @param  list<string>  $reaches
     * @return void
     */
    #[DataProvider('provideDispatcherReaches')]
    public function testTheScannerFindsLaravelsDispatcherAndTheEventHelper(string $code, array $reaches): void
    {
        $source = "<?php\n\nnamespace SineMacula\\Laravel\\Mfa\\Verification;\n\n{$code}\n";

        self::assertSame($reaches, self::dispatchersIn($source));
    }

    /**
     * The scanner finds a package name however a class names it: imported
     * alone, aliased, grouped, as a function or a constant (alone or within a
     * group), through an alias or relative to its namespace, fully qualified in
     * code or in a docblock; and nothing for an unqualified name, a closure's
     * `use`, or a name outside the package.
     *
     * @return void
     */
    public function testTheScannerFindsEveryWayOfNamingAClass(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Mfa\Verification;

            use Illuminate\Support\Str;
            use SineMacula\Laravel\Mfa\Codes\CodeKeys;
            use SineMacula\Laravel\Mfa\Http as Web;
            use SineMacula\Laravel\Mfa\Events\{VerificationFailed, Enums\Outcome as Result};
            use function SineMacula\Laravel\Mfa\Support\helper;
            use SineMacula\Laravel\Mfa\{function Codes\issue, const Http\FLAG};

            /**
             * @see \SineMacula\Laravel\Mfa\Proofs\ProofBinding
             */
            final class Example
            {
                use Concerns\ChecksSubmissions;

                /** @var \SineMacula\Laravel\Mfa\Models\Factor */
                private $factor;

                public function run(): void
                {
                    $value = 1;

                    $callback = static function () use ($value): int {
                        return $value;
                    };

                    new Web\Middleware\RequireMfa;
                    new \SineMacula\Laravel\Mfa\Database\AfterStorageCommit($callback);
                    new namespace\SubmissionRoutes;
                    new VerificationResult;
                    Str::random();
                }
            }
            PHP;

        $names = self::withinPackage(self::namesIn($source));

        sort($names);

        self::assertSame([
            'Codes\CodeKeys',
            'Codes\issue',
            'Database\AfterStorageCommit',
            'Events\Enums\Outcome',
            'Events\VerificationFailed',
            'Http',
            'Http\FLAG',
            'Http\Middleware\RequireMfa',
            'Models\Factor',
            'Proofs\ProofBinding',
            'Support\helper',
            'Verification\Concerns\ChecksSubmissions',
            'Verification\SubmissionRoutes',
        ], $names);
    }

    /**
     * The scanner reads the imports of a bracketed namespace as imports, gives
     * each namespace its own aliases, reads a closure's `use` at the top of a
     * namespace as code, and resolves names in the global namespace from its
     * root.
     *
     * @return void
     */
    public function testTheScannerReadsEachBracketedNamespaceOnItsOwn(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Mfa\Models {

                use SineMacula\Laravel\Mfa\Codes\CodeKeys;
                use SineMacula\Laravel\Mfa\Http as Web;

                $resolve = static function () use ($container): void {
                    new \SineMacula\Laravel\Mfa\Verification\VerificationService;
                };

                final class Example
                {
                    use Concerns\HasCodes;
                }
            }

            namespace {

                new Web\Middleware\RequireMfa;
                new SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
                new namespace\SineMacula\Laravel\Mfa\Config\IntegerSetting;
            }
            PHP;

        $names = self::withinPackage(self::namesIn($source));

        sort($names);

        self::assertSame([
            'Codes\CodeKeys',
            'Config\IntegerSetting',
            'Database\AfterStorageCommit',
            'Http',
            'Models\Concerns\HasCodes',
            'Verification\VerificationService',
        ], $names);
    }

    /**
     * A qualified name resolves through the class or namespace import its first
     * segment names, whatever its case, and not through a function's or a
     * constant's import of the same name, alone or within a group; a rule
     * catches a forbidden name whatever its case, fully qualified in code or in
     * a docblock.
     *
     * @return void
     */
    public function testTheScannerResolvesAQualifiedNameAsPhpDoes(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Mfa\Models;

            use SineMacula\Laravel\Mfa as Mfa;
            use SineMacula\Laravel\Mfa\Http as Web;
            use SineMacula\Laravel\Mfa\Codes as Delivery;
            use function Other\Mfa;
            use CONST Other\Web;
            use Other\{FUNCTION deliver as Delivery, const Mfa};

            /**
             * @see \sinemacula\laravel\mfa\verification\VerificationService
             */
            final class Example
            {
                public function run(): void
                {
                    new Mfa\Codes\CodeKeys;
                    new mfa\Verification\Submission;
                    new WEB\Middleware\RequireMfa;
                    new delivery\DeliveredCodes;
                    new \sinemacula\laravel\mfa\codes\IssuedCode;
                }
            }
            PHP;

        $names = self::withinPackage(self::namesIn($source));

        sort($names);

        self::assertSame([
            'Codes',
            'Codes\CodeKeys',
            'Codes\DeliveredCodes',
            'Http',
            'Http\Middleware\RequireMfa',
            'Verification\Submission',
            'codes\IssuedCode',
            'verification\VerificationService',
        ], $names);

        self::assertSame([
            'Models\Example names Codes',
            'Models\Example names Codes\CodeKeys',
            'Models\Example names Codes\DeliveredCodes',
            'Models\Example names Http',
            'Models\Example names Http\Middleware\RequireMfa',
            'Models\Example names Verification\Submission',
            'Models\Example names codes\IssuedCode',
            'Models\Example names verification\VerificationService',
        ], self::violations(['Models\Example' => $names], ['models'], [], ['CODES', 'Verification', 'Http'], []));
    }

    /**
     * What each class a rule applies to names that the rule forbids.
     *
     * @param  array<string, list<string>>  $classes
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return list<string>
     */
    private static function violations(array $classes, array $from, array $except, array $forbids, array $allows): array
    {
        $violations = [];

        foreach ($classes as $class => $names) {

            if (!self::isWithin($class, $from) || self::isWithin($class, $except)) {
                continue;
            }

            foreach ($names as $name) {

                if (!self::isWithin($name, $forbids) || self::isWithin($name, $allows)) {
                    continue;
                }

                $violations[] = "{$class} names {$name}";
            }
        }

        return $violations;
    }

    /**
     * Every class of the package and the package names it names, relative to
     * the package.
     *
     * @return array<string, list<string>>
     */
    private static function packageNames(): array
    {
        return array_map(self::withinPackage(...), self::names());
    }

    /**
     * Every class of the package and every name it names, fully qualified, read
     * once.
     *
     * @return array<string, list<string>>
     */
    private static function names(): array
    {
        return self::$names ??= array_map(self::namesIn(...), self::sources());
    }

    /**
     * The package names among the names, relative to the package.
     *
     * @param  list<string>  $names
     * @return list<string>
     */
    private static function withinPackage(array $names): array
    {
        $package = array_filter($names, static fn (string $name): bool => strncasecmp($name, self::PACKAGE, strlen(self::PACKAGE)) === 0);

        return array_values(array_map(static fn (string $name): string => substr($name, strlen(self::PACKAGE)), $package));
    }

    /**
     * Every class of the package and its source, by its name relative to the
     * package, read once.
     *
     * @return array<string, string>
     */
    private static function sources(): array
    {
        if (self::$sources !== null) {
            return self::$sources;
        }

        $source  = dirname(__DIR__, 3) . '/src/';
        $files   = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($source, \FilesystemIterator::SKIP_DOTS));
        $sources = [];

        foreach ($files as $file) {

            assert($file instanceof \SplFileInfo);

            if ($file->getExtension() !== 'php') {
                continue;
            }

            $class = str_replace('/', '\\', substr($file->getPathname(), strlen($source), -4));

            $sources[$class] = (string) file_get_contents($file->getPathname());
        }

        ksort($sources);

        return self::$sources = $sources;
    }

    /**
     * How the source reaches Laravel's dispatcher: each of its names it names,
     * in the order of `DISPATCHERS`, then, in the order they appear, `event()`
     * for each call of the helper and `'events'` for each use of its container
     * key.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function dispatchersIn(string $source): array
    {
        $names   = array_map(strtolower(...), self::namesIn($source));
        $reaches = array_values(array_filter(self::DISPATCHERS, static fn (string $dispatcher): bool => in_array(strtolower($dispatcher), $names, true)));
        $tokens  = self::tokens($source);

        foreach (array_keys($tokens) as $index) {

            $reach = self::reachAt($tokens, $index);

            if ($reach === null) {
                continue;
            }

            $reaches[] = $reach;
        }

        return $reaches;
    }

    /**
     * How the token at the index reaches Laravel's dispatcher, if it does:
     * `event()` for a call of the helper, or the quoted container key.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return ?string
     */
    private static function reachAt(array $tokens, int $index): ?string
    {
        if (self::isEventCall($tokens, $index)) {
            return 'event()';
        }

        if (self::isDispatcherKey($tokens[$index])) {
            return '\'' . self::DISPATCHER_KEY . '\'';
        }

        return null;
    }

    /**
     * Whether the token is the dispatcher's container key as a string literal,
     * in single or double quotes.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @return bool
     */
    private static function isDispatcherKey(array|string $token): bool
    {
        return is_array($token)
            && $token[0]                === T_CONSTANT_ENCAPSED_STRING
            && substr($token[1], 1, -1) === self::DISPATCHER_KEY;
    }

    /**
     * Whether the token at the index calls the global `event()` helper: the
     * name `event`, unqualified or fully qualified, followed by `(`, and not a
     * method called through `->`, `?->` or `::` or a function being declared.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return bool
     */
    private static function isEventCall(array $tokens, int $index): bool
    {
        $token = $tokens[$index];

        if (!is_array($token) || ($tokens[$index + 1] ?? null) !== '(') {
            return false;
        }

        if ($token[0] === T_NAME_FULLY_QUALIFIED) {
            return strtolower($token[1]) === '\event';
        }

        $before = $tokens[$index - 1] ?? null;

        return $token[0]             === T_STRING
            && strtolower($token[1]) === 'event'
            && !(is_array($before) && in_array($before[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION], true));
    }

    /**
     * The distinct names the source names, fully qualified.
     *
     * An import is read as one statement, so its names are not read again as
     * names in code; each namespace's body, whether it ends at the next
     * `namespace` or at its closing brace, has its own aliases. The names of a
     * trait's or a closure's `use` are read as names in code.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function namesIn(string $source): array
    {
        $tokens    = self::tokens($source);
        $depths    = self::depths($tokens);
        $namespace = '';
        $body      = 0;
        $aliases   = [];
        $names     = [];

        for ($index = 0, $count = count($tokens); $index < $count; $index++) {

            [$id, $text] = is_array($tokens[$index]) ? $tokens[$index] : [null, $tokens[$index]];

            if ($id === T_NAMESPACE) {
                [$namespace, $body, $index] = self::declared($tokens, $depths, $index);

                $aliases = [];
            } elseif ($id === T_USE && self::isImport($tokens, $depths, $index, $body)) {
                [$statement, $index] = self::statement($tokens, $index + 1);

                array_push($names, ...self::imports($statement, $aliases));
            } elseif ($id === T_DOC_COMMENT) {
                array_push($names, ...self::documented($text));
            } elseif ($id !== null) {
                $names[] = self::qualified($id, $text, $namespace, $aliases);
            }
        }

        return array_values(array_unique(array_filter($names, static fn (?string $name): bool => $name !== null)));
    }

    /**
     * The namespace declared at the index, the depth of the braces its imports
     * sit in, and the index of its last token before its body.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  list<int>  $depths
     * @param  int  $index
     * @return array{0: string, 1: int, 2: int}
     */
    private static function declared(array $tokens, array $depths, int $index): array
    {
        $namespace = is_array($tokens[$index + 1]) ? self::text($tokens[++$index]) : '';
        $body      = ($tokens[$index + 1] ?? null) === '{' ? $depths[$index] + 1 : $depths[$index];

        return [$namespace, $body, $index];
    }

    /**
     * Whether the `use` at the index is an import: one directly in the
     * namespace's body, not a trait's in a class or a closure's after its
     * parameters.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  list<int>  $depths
     * @param  int  $index
     * @param  int  $body
     * @return bool
     */
    private static function isImport(array $tokens, array $depths, int $index, int $body): bool
    {
        return $depths[$index] === $body && $tokens[$index - 1] !== ')';
    }

    /**
     * The source's tokens, without whitespace and plain comments.
     *
     * @param  string  $source
     * @return list<array{0: int, 1: string, 2: int}|string>
     */
    private static function tokens(string $source): array
    {
        $meaningful = static fn (array|string $token): bool => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT], true);

        return array_values(array_filter(token_get_all($source), $meaningful));
    }

    /**
     * How many braces are open before each token.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @return list<int>
     */
    private static function depths(array $tokens): array
    {
        $depths = [];
        $depth  = 0;

        foreach ($tokens as $token) {

            $depths[] = $depth;

            $depth += match (true) {
                $token === '{', is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true) => 1,
                $token === '}'                                                                                            => -1,
                default                                                                                                   => 0,
            };
        }

        return $depths;
    }

    /**
     * The import statement that starts at the index, as text without its
     * whitespace, and the index of its `;`.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return array{0: string, 1: int}
     */
    private static function statement(array $tokens, int $index): array
    {
        $statement = '';

        for (; ($tokens[$index] ?? ';') !== ';'; $index++) {
            $statement .= self::text($tokens[$index]);
        }

        return [$statement, $index];
    }

    /**
     * The text of the token, with a space around `as` and after `function` or
     * `const`, the words an import statement may hold.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @return string
     */
    private static function text(array|string $token): string
    {
        if (!is_array($token)) {
            return $token;
        }

        return match ($token[0]) {
            T_AS                => ' as ',
            T_FUNCTION, T_CONST => $token[1] . ' ',
            default             => $token[1],
        };
    }

    /**
     * The names an import statement imports, recording the alias each class or
     * namespace import gives by its lower case. A qualified name resolves only
     * through those, without regard to case: a function's or a constant's
     * import of the same name is kept apart from them.
     *
     * @param  string  $statement
     * @param  array<string, string>  $aliases
     * @return list<string>
     */
    private static function imports(string $statement, array &$aliases): array
    {
        [$kind, $statement] = self::kind($statement, '');

        $prefix = '';

        if (preg_match('/^(.*)\\\\\{(.*)\}$/', $statement, $group) === 1) {
            [, $prefix, $statement] = $group;

            $prefix .= '\\';
        }

        $names = [];

        foreach (explode(',', $statement) as $import) {

            [$member, $import] = self::kind($import, $kind);

            $parts = explode(' as ', $import);
            $name  = ltrim($prefix . $parts[0], '\\');
            $alias = $parts[1] ?? substr((string) strrchr('\\' . $name, '\\'), 1);

            if ($member === '') {
                $aliases[strtolower($alias)] = $name;
            }

            $names[] = $name;
        }

        return $names;
    }

    /**
     * What the import imports, `function`, `const` or `''` for a class or a
     * namespace, and the import without the word that gives it: a whole
     * statement's, or one member's of a group, which imports what its statement
     * does unless it gives its own.
     *
     * @param  string  $import
     * @param  string  $kind
     * @return array{0: string, 1: string}
     */
    private static function kind(string $import, string $kind): array
    {
        if (preg_match('/^(function|const) (.*)$/i', $import, $match) === 1) {
            return [strtolower($match[1]), $match[2]];
        }

        return [$kind, $import];
    }

    /**
     * The fully qualified name a name token stands for: a qualified name
     * through the alias its first segment names, whatever its case, or else
     * relative to the namespace; `null` for any other token.
     *
     * @param  int  $id
     * @param  string  $text
     * @param  string  $namespace
     * @param  array<string, string>  $aliases
     * @return ?string
     */
    private static function qualified(int $id, string $text, string $namespace, array $aliases): ?string
    {
        if ($id === T_NAME_FULLY_QUALIFIED) {
            return substr($text, 1);
        }

        if ($id === T_NAME_RELATIVE) {
            return ltrim($namespace . substr($text, strlen('namespace')), '\\');
        }

        if ($id !== T_NAME_QUALIFIED) {
            return null;
        }

        [$first, $rest] = explode('\\', $text, 2);

        $alias = strtolower($first);

        return isset($aliases[$alias]) ? $aliases[$alias] . '\\' . $rest : ltrim($namespace . '\\' . $text, '\\');
    }

    /**
     * The fully qualified names a docblock gives.
     *
     * @param  string  $docblock
     * @return list<string>
     */
    private static function documented(string $docblock): array
    {
        preg_match_all(self::DOCBLOCK_NAME, $docblock, $matches);

        return $matches[1];
    }

    /**
     * Whether the name is one of the namespaces or classes, or inside one of
     * them, without regard to case; `*` stands for the whole package.
     *
     * @param  string  $name
     * @param  list<string>  $scopes
     * @return bool
     */
    private static function isWithin(string $name, array $scopes): bool
    {
        $name = strtolower($name);

        foreach (array_map(strtolower(...), $scopes) as $scope) {
            if ($scope === '*' || $name === $scope || str_starts_with($name, $scope . '\\')) {
                return true;
            }
        }

        return false;
    }
}
