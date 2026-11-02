<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Database\DeadlockException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\StorageTransaction;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Secrets\ExceptionScrubber;
use SineMacula\Laravel\Mfa\Secrets\QueryExceptionMask;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use Tests\TestCase;

/**
 * A failed query's exception keeps its class and code and what says what went
 * wrong, and nothing the query was given: not in its message, its bindings,
 * what it wraps or the arguments its trace recorded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(QueryExceptionMask::class)]
#[CoversClass(ExceptionScrubber::class)]
#[CoversClass(StorageTransaction::class)]
#[CoversClass(WriteConnection::class)]
final class QueryExceptionMaskTest extends TestCase
{
    /** @var string What a query was given. */
    private const string SECRET = 'person@example.test';

    /** @var string A statement on a package table. */
    private const string SQL = 'insert into "mfa_factors" ("destination") values (?)';

    /** @var false|string The setting that keeps arguments out of an exception's trace, as it was. */
    private false|string $ignoredArguments = false;

    /**
     * Keep arguments in an exception's trace, so they can be searched.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ignoredArguments = ini_set('zend.exception_ignore_args', '0');
    }

    /**
     * Put the setting back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->ignoredArguments !== false) {
            ini_set('zend.exception_ignore_args', $this->ignoredArguments);
        }

        parent::tearDown();
    }

    /**
     * The message becomes the SQLSTATE, the driver error number, the connection
     * and the SQL with placeholders.
     *
     * @return void
     */
    public function testTheMessageSaysWhatFailedAndNothingItWasGiven(): void
    {
        $exception = $this->failure();

        self::assertStringContainsString(self::SECRET, $exception->getMessage());

        QueryExceptionMask::mask($exception);

        self::assertSame('SQLSTATE[23000]: driver error 1062 (Connection: testing, SQL: ' . self::SQL . ')', $exception->getMessage());
    }

    /**
     * A previous exception's message becomes the SQLSTATE and the driver error
     * number, and nothing the driver quoted stays.
     *
     * @return void
     */
    public function testAPreviousMessageKeepsOnlyTheReason(): void
    {
        $exception = $this->failure();
        $previous  = $exception->getPrevious();

        QueryExceptionMask::mask($exception);

        self::assertInstanceOf(\PDOException::class, $previous);
        self::assertSame('SQLSTATE[23000]: driver error 1062', $previous->getMessage());
        self::assertSame(['23000', 1062, null], $previous->errorInfo);
    }

    /**
     * The bindings are emptied, and the driver's text in `errorInfo` is cleared
     * with its SQLSTATE and number kept.
     *
     * @return void
     */
    public function testTheBindingsAndDriverTextGo(): void
    {
        $exception = $this->failure();

        QueryExceptionMask::mask($exception);

        self::assertSame([], $exception->getBindings());
        self::assertSame(['23000', 1062, null], $exception->errorInfo);
        self::assertSame(self::SQL, $exception->getSql());
    }

    /**
     * Its class and code stay, so it is still caught as what it is.
     *
     * @return void
     */
    public function testAUniqueViolationStaysCatchableWithItsCode(): void
    {
        $exception = new UniqueConstraintViolationException('testing', self::SQL, [self::SECRET], $this->driverFailure());

        QueryExceptionMask::mask($exception);

        self::assertInstanceOf(UniqueConstraintViolationException::class, $exception);
        self::assertSame('23000', $exception->getCode());
    }

    /**
     * Without an `errorInfo`, the reason falls back on the code alone.
     *
     * @return void
     */
    public function testWithoutErrorInfoTheCodeIsTheState(): void
    {
        $previous = new \RuntimeException('Refused ' . self::SECRET, 7);

        $exception = new QueryException('testing', self::SQL, [self::SECRET], $previous);

        QueryExceptionMask::mask($exception);

        self::assertSame('SQLSTATE[7]', $previous->getMessage());
        self::assertStringStartsWith('SQLSTATE[7] (Connection: testing', $exception->getMessage());
    }

    /**
     * An `errorInfo` with no driver text is left as it is.
     *
     * @return void
     */
    public function testAnErrorInfoWithoutDriverTextIsKept(): void
    {
        $previous = new \PDOException('SQLSTATE[HY000]: failed');

        $previous->errorInfo = ['HY000', 1];

        $exception = new QueryException('testing', self::SQL, [], $previous);

        QueryExceptionMask::mask($exception);

        self::assertSame(['HY000', 1], $previous->errorInfo);
    }

    /**
     * The arguments a trace recorded lose what the query was given, whatever
     * frame holds them, a value in another frame included.
     *
     * @return void
     */
    public function testTheTraceLosesWhatItWasGiven(): void
    {
        $exception = $this->failedThrough('prefix ' . self::SECRET . ' suffix');

        self::assertStringContainsString(self::SECRET, serialize($this->arguments($exception)));

        QueryExceptionMask::mask($exception);

        self::assertStringNotContainsString(self::SECRET, serialize($this->arguments($exception)));
    }

    /**
     * Every query exception a chain holds gives up its bindings, and only the
     * first is summarised.
     *
     * @return void
     */
    public function testANestedQueryExceptionIsMaskedToo(): void
    {
        $inner = $this->failure();
        $outer = new QueryException('testing', self::SQL, ['other'], $inner);

        QueryExceptionMask::mask($outer);

        self::assertSame([], $inner->getBindings());
        self::assertSame([], $outer->getBindings());
        self::assertStringNotContainsString('Connection', $inner->getMessage());
    }

    /**
     * Something other than a query exception in the chain does not stop what
     * lies behind it being masked.
     *
     * @return void
     */
    public function testTheChainIsFollowedPastAnythingElse(): void
    {
        $inner  = $this->failure();
        $driver = $this->driverFailure();
        $middle = new \RuntimeException('Passed on ' . self::SECRET, 0, $inner);
        $outer  = new QueryException('testing', self::SQL, [], new \RuntimeException('Passed on', 0, $middle));

        (new \ReflectionProperty(\Exception::class, 'previous'))->setValue($inner, $driver);

        QueryExceptionMask::mask($outer);

        self::assertSame([], $inner->getBindings());
        self::assertSame(['23000', 1062, null], $driver->errorInfo);
        self::assertStringNotContainsString(self::SECRET, $middle->getMessage());
    }

    /**
     * What every query exception in a chain was given is known in the trace,
     * not only what the last was.
     *
     * @return void
     */
    public function testEveryBindingInTheChainIsKnownInTheTrace(): void
    {
        $outer = $this->throughBoth('prefix alpha-value suffix', 'prefix beta-value suffix');

        QueryExceptionMask::mask($outer);

        $arguments = serialize($this->arguments($outer));

        self::assertStringNotContainsString('alpha-value', $arguments);
        self::assertStringNotContainsString('beta-value', $arguments);
    }

    /**
     * The SQLSTATE comes from `errorInfo` first, where a driver gives one apart
     * from the code.
     *
     * @return void
     */
    public function testTheStateComesFromTheErrorInfo(): void
    {
        $previous = new \PDOException('SQLSTATE[42S02]: not found');

        $previous->errorInfo = ['42S02', 1146, 'text'];

        (new \ReflectionProperty(\Exception::class, 'code'))->setValue($previous, 'other');

        $exception = new QueryException('testing', self::SQL, [], $previous);

        QueryExceptionMask::mask($exception);

        self::assertStringStartsWith('SQLSTATE[42S02]: driver error 1146', $exception->getMessage());
    }

    /**
     * On the report path, a failure on a package table is masked.
     *
     * @return void
     */
    public function testTheScrubberMasksAFailureOnAPackageTable(): void
    {
        $exception = $this->failure();
        $wrapper   = new \RuntimeException('Wrapped.', 0, $exception);

        ExceptionScrubber::scrub($wrapper);

        self::assertSame([], $exception->getBindings());
        self::assertStringNotContainsString(self::SECRET, $exception->getMessage());
        self::assertSame('Wrapped.', $wrapper->getMessage());
    }

    /**
     * It finds a table under its configured name.
     *
     * @return void
     */
    public function testTheScrubberFindsAConfiguredTable(): void
    {
        config()->set('mfa.factor.table', 'renamed_factors');

        $exception = new QueryException('testing', 'select * from "renamed_factors" where "d" = ?', [self::SECRET], $this->driverFailure());

        ExceptionScrubber::scrub($exception);

        self::assertSame([], $exception->getBindings());
    }

    /**
     * An application's own failure on its own table is left as it is, bar the
     * scrubbing every exception gets.
     *
     * @return void
     */
    public function testTheScrubberLeavesAnApplicationsOwnFailure(): void
    {
        $exception = new QueryException('testing', 'select * from "orders" where "id" = ?', ['41'], $this->driverFailure());

        ExceptionScrubber::scrub($exception);

        self::assertSame(['41'], $exception->getBindings());
        self::assertStringContainsString('where "id" = 41', $exception->getMessage());
    }

    /**
     * A failure leaving a package transaction is masked, whatever
     * `mfa.secrets.redact` says, and what is not a query failure is left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureLeavingATransactionIsMasked(): void
    {
        config()->set('mfa.secrets.redact', false);

        $exception = $this->failure();

        try {
            StorageTransaction::run(static fn (): never => throw $exception);
        } catch (QueryException $caught) {
            self::assertSame($exception, $caught);
        }

        self::assertSame([], $exception->getBindings());

        $other = new \RuntimeException('Not a query ' . self::SECRET);

        try {
            StorageTransaction::run(static fn (): never => throw $other);
        } catch (\RuntimeException $caught) {
            self::assertSame('Not a query ' . self::SECRET, $caught->getMessage());
        }
    }

    /**
     * A deadlock exception above a failed query loses the message it copied and
     * keeps what Laravel recognises it by, and the query under it is masked.
     *
     * @return void
     */
    public function testADeadlockAboveAFailedQueryLosesWhatItCopied(): void
    {
        $query    = $this->failure();
        $deadlock = new DeadlockException($query->getMessage(), 0, $query);

        QueryExceptionMask::maskChain($deadlock);

        self::assertSame('deadlock detected: SQLSTATE[23000]: driver error 1062 (Connection: testing, SQL: ' . self::SQL . ')', $deadlock->getMessage());
        self::assertSame([], $query->getBindings());
        self::assertStringNotContainsString(self::SECRET, $query->getMessage());
    }

    /**
     * Each deadlock exception a chain holds above a failed query is rewritten,
     * as a transaction nested twice wraps the wrapper.
     *
     * @return void
     */
    public function testEveryDeadlockAboveAFailedQueryIsRewritten(): void
    {
        $query = $this->failure();
        $inner = new DeadlockException($query->getMessage(), 0, $query);
        $outer = new DeadlockException($inner->getMessage(), 0, $inner);

        QueryExceptionMask::maskChain($outer);

        self::assertStringNotContainsString(self::SECRET, $inner->getMessage());
        self::assertStringNotContainsString(self::SECRET, $outer->getMessage());
    }

    /**
     * A deadlock exception with no failed query under it has nothing to lose.
     *
     * @return void
     */
    public function testADeadlockWithoutAFailedQueryIsLeftAlone(): void
    {
        $deadlock = new DeadlockException('Lock wait timeout exceeded', 0, new \PDOException('Lock wait timeout exceeded'));

        QueryExceptionMask::maskChain($deadlock);

        self::assertSame('Lock wait timeout exceeded', $deadlock->getMessage());
    }

    /**
     * The arguments a deadlock exception's trace recorded lose what the query
     * under it was given, every binding in the chain among them.
     *
     * @return void
     */
    public function testADeadlocksTraceLosesWhatTheQueryWasGiven(): void
    {
        $deadlock = $this->deadlockThrough('prefix ' . self::SECRET . ' suffix');

        self::assertStringContainsString(self::SECRET, serialize($this->arguments($deadlock)));

        QueryExceptionMask::maskChain($deadlock);

        self::assertStringNotContainsString(self::SECRET, serialize($this->arguments($deadlock)));
    }

    /**
     * What a deadlock exception wraps may hold more than one failed query, and
     * what each was given is known in its trace.
     *
     * @return void
     */
    public function testEveryBindingBelowADeadlockIsKnownInItsTrace(): void
    {
        $deadlock = $this->deadlockAboveBoth('prefix alpha-value suffix', 'prefix beta-value suffix');

        QueryExceptionMask::maskChain($deadlock);

        $arguments = serialize($this->arguments($deadlock));

        self::assertStringNotContainsString('alpha-value', $arguments);
        self::assertStringNotContainsString('beta-value', $arguments);
    }

    /**
     * Something other than a query exception between two does not hide what the
     * deeper one was given from the trace.
     *
     * @return void
     */
    public function testABindingBehindSomethingElseIsKnownInTheTrace(): void
    {
        $outer = $this->throughSomethingElse('prefix beta-value suffix');

        QueryExceptionMask::mask($outer);

        self::assertStringNotContainsString('beta-value', serialize($this->arguments($outer)));
    }

    /**
     * The scrubber rewrites a deadlock exception above a failure on one of the
     * package's tables.
     *
     * @return void
     */
    public function testTheScrubberMasksADeadlockAboveAPackageFailure(): void
    {
        $query    = $this->failure();
        $deadlock = new DeadlockException($query->getMessage(), 0, $query);

        ExceptionScrubber::scrub($deadlock);

        self::assertStringStartsWith('deadlock detected: SQLSTATE[23000]', $deadlock->getMessage());
        self::assertSame([], $query->getBindings());
    }

    /**
     * The scrubber leaves a deadlock exception above an application's own
     * failure as it does the failure.
     *
     * @return void
     */
    public function testTheScrubberLeavesADeadlockAboveAnApplicationsOwnFailure(): void
    {
        $query    = new QueryException('testing', 'insert into "orders" ("reference") values (?)', ['order-reference-1'], $this->driverFailure());
        $deadlock = new DeadlockException($query->getMessage(), 0, $query);

        ExceptionScrubber::scrub($deadlock);

        self::assertStringContainsString('order-reference-1', $deadlock->getMessage());
        self::assertSame(['order-reference-1'], $query->getBindings());
    }

    /**
     * A deadlock exception leaving a package transaction is masked, whatever
     * `mfa.secrets.redact` says.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeadlockLeavingATransactionIsMasked(): void
    {
        config()->set('mfa.secrets.redact', false);

        $query    = $this->failure();
        $deadlock = new DeadlockException($query->getMessage(), 0, $query);

        try {
            StorageTransaction::run(static fn (): never => throw $deadlock);
        } catch (DeadlockException $caught) {
            self::assertSame($deadlock, $caught);
        }

        self::assertStringNotContainsString(self::SECRET, $deadlock->getMessage());
        self::assertSame([], $query->getBindings());
    }

    /**
     * A failure leaving a pin on the write connection is masked, and the pin is
     * released.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureLeavingAPinIsMasked(): void
    {
        $exception = $this->failure();

        try {
            WriteConnection::during(new Factor, static fn (): never => throw $exception);
        } catch (QueryException) {
            self::assertSame([], $exception->getBindings());
        }

        self::assertSame([], $exception->getBindings());
    }

    /**
     * A failed save of a factor leaves with nothing the factor held, even with
     * no transaction open.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     */
    public function testAFailedSaveOfAFactorIsMasked(): void
    {
        $exception = $this->failure();

        $factor = new Factor(['type' => 'email', 'destination' => self::SECRET]);

        Factor::saving(static fn (Model $model): never => throw $exception);

        try {
            $factor->persist();

            self::fail('The save must fail.');
        } catch (QueryException $caught) {
            self::assertSame($exception, $caught);
        }

        self::assertSame([], $exception->getBindings());
        self::assertStringNotContainsString(self::SECRET, $exception->getMessage());
    }

    /**
     * Anything that interpolates what the query was given.
     *
     * @return \Illuminate\Database\QueryException
     */
    private function failure(): QueryException
    {
        return new QueryException('testing', self::SQL, [self::SECRET, 41, null], $this->driverFailure());
    }

    /**
     * What a driver raises, quoting the stored value.
     *
     * @return \PDOException
     */
    private function driverFailure(): \PDOException
    {
        $failure = new \PDOException('SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry \'' . self::SECRET . '\' for key');

        $failure->errorInfo = ['23000', 1062, 'Duplicate entry \'' . self::SECRET . '\' for key'];

        (new \ReflectionProperty(\Exception::class, 'code'))->setValue($failure, '23000');

        return $failure;
    }

    /**
     * A failure whose trace records the value, in a frame outside the package
     * that received it.
     *
     * @param  string  $value
     * @return \Illuminate\Database\QueryException
     */
    private function failedThrough(string $value): QueryException
    {
        try {
            $this->throwing($value);
        } catch (QueryException $exception) {
            return $exception;
        }
    }

    /**
     * Throw a failure bound to the secret, with the value in this frame.
     *
     * @param  string  $value
     * @return never
     *
     * @throws \Illuminate\Database\QueryException
     */
    private function throwing(string $value): never
    {
        throw $this->failure();
    }

    /**
     * A failure wrapping another, each bound to its own value, with both values
     * in this frame.
     *
     * @param  string  $first
     * @param  string  $second
     * @return \Illuminate\Database\QueryException
     */
    private function throughBoth(string $first, string $second): QueryException
    {
        $inner = new QueryException('testing', self::SQL, ['beta-value'], $this->driverFailure());

        return new QueryException('testing', self::SQL, ['alpha-value'], $inner);
    }

    /**
     * A failure wrapping something else that wraps another failure, bound to a
     * value this frame holds, which the outer failure was not given.
     *
     * @param  string  $value
     * @return \Illuminate\Database\QueryException
     */
    private function throughSomethingElse(string $value): QueryException
    {
        $inner = new QueryException('testing', self::SQL, ['beta-value'], $this->driverFailure());

        return new QueryException('testing', self::SQL, [], new \RuntimeException('Passed on', 0, $inner));
    }

    /**
     * A deadlock above a failure bound to the secret, whose trace records the
     * value in a frame outside the package that received it.
     *
     * @param  string  $value
     * @return \Illuminate\Database\DeadlockException
     */
    private function deadlockThrough(string $value): DeadlockException
    {
        $query = $this->failure();

        return new DeadlockException($query->getMessage(), 0, $query);
    }

    /**
     * A deadlock above a failure wrapping another, each bound to its own value,
     * with both values in this frame.
     *
     * @param  string  $first
     * @param  string  $second
     * @return \Illuminate\Database\DeadlockException
     */
    private function deadlockAboveBoth(string $first, string $second): DeadlockException
    {
        $inner = new QueryException('testing', self::SQL, ['beta-value'], $this->driverFailure());
        $outer = new QueryException('testing', self::SQL, ['alpha-value'], $inner);

        return new DeadlockException($outer->getMessage(), 0, $outer);
    }

    /**
     * The arguments every frame of the exception's trace recorded.
     *
     * @param  \Throwable  $throwable
     * @return list<mixed>
     */
    private function arguments(\Throwable $throwable): array
    {
        $arguments = [];

        foreach ($throwable->getTrace() as $frame) {
            $arguments[] = array_map(static fn (mixed $argument): mixed => is_object($argument) ? RevealedSecret::REDACTED : $argument, $frame['args'] ?? []);
        }

        return $arguments;
    }
}
