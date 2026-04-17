<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use Tests\Fixtures\AbstractFactorStub;
use Tests\Fixtures\CallOrderTrackingFactor;
use Tests\Fixtures\DispatchTrackingOtpDriver;
use Tests\Fixtures\Exceptions\DispatchTransportFailureException;
use Tests\Fixtures\TestUser;

/**
 * Shared scaffolding for the `AbstractOtpDriver` test family.
 *
 * Centralises the driver / factor builders used by the issuance,
 * verification, and alphabet-config tests so each file stays under
 * the project's max-methods-per-class threshold without duplicating
 * the stub surface across test classes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
trait InteractsWithAbstractOtpDriver
{
    /** @var string Address fixture reused across the persisted-factor scaffolding helpers. */
    protected const string OTP_RECIPIENT = 'otp@example.com';

    /**
     * Build a concrete subclass of the abstract driver that records
     * every `dispatch()` invocation, optionally throws, and captures
     * the order of the dispatch / issueCode / persist calls against
     * an externally supplied tracker array.
     *
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  int  $maxAttempts
     * @param  bool  $throwOnDispatch
     * @param  ?string  $alphabet
     * @param  array<int, string>  $orderTracker
     * @return \Tests\Fixtures\DispatchTrackingOtpDriver
     */
    protected function makeDriver(
        int $codeLength = 6,
        int $expiry = 10,
        int $maxAttempts = 3,
        bool $throwOnDispatch = false,
        ?string $alphabet = null,
        array &$orderTracker = [],
    ): DispatchTrackingOtpDriver {
        $driver = new class ($codeLength, $expiry, $maxAttempts, $alphabet, $throwOnDispatch) extends DispatchTrackingOtpDriver {
            /**
             * Wire the configured driver state and the dispatch
             * behaviour switch.
             *
             * @param  int  $codeLength
             * @param  int  $expiry
             * @param  int  $maxAttempts
             * @param  ?string  $alphabet
             * @param  bool  $throwOnDispatch
             * @return void
             */
            public function __construct(
                int $codeLength,
                int $expiry,
                int $maxAttempts,
                ?string $alphabet,
                private readonly bool $throwOnDispatch,
            ) {
                parent::__construct($codeLength, $expiry, $maxAttempts, $alphabet);
            }

            /**
             * Capture every dispatch invocation; throw on demand to
             * simulate transport failure.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
             * @param  string  $code
             * @return void
             *
             * @throws \Tests\Fixtures\Exceptions\DispatchTransportFailureException
             */
            protected function dispatch(
                EloquentFactor $factor,
                #[\SensitiveParameter]
                string $code,
            ): void {
                $this->order[]      = 'dispatch';
                $this->dispatched[] = ['factor' => $factor, 'code' => $code];

                if ($this->throwOnDispatch) {
                    throw new DispatchTransportFailureException('transport failure');
                }
            }
        };

        $driver->bindOrderRef($orderTracker);

        return $driver;
    }

    /**
     * Persist a `FactorModel` subclass whose `issueCode()` and
     * `persist()` methods append to the shared order tracker so call
     * ordering can be asserted from the outside.
     *
     * @param  array<int, string>  $tracker
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function createTrackingFactor(array &$tracker): FactorModel
    {
        $user = TestUser::query()->create([
            'email'       => self::OTP_RECIPIENT,
            'mfa_enabled' => true,
        ]);

        $factor = new CallOrderTrackingFactor;
        $factor->bindTracker($tracker);
        $factor->driver               = 'email';
        $factor->recipient            = self::OTP_RECIPIENT;
        $factor->authenticatable_type = $user->getMorphClass();
        $factor->authenticatable_id   = (string) $user->id;
        $factor->save();

        return $factor;
    }

    /**
     * Create a persisted Eloquent factor wired to a freshly inserted
     * test user so both dispatch and persistence can be observed.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    protected function createEloquentFactor(): FactorModel
    {
        $user = TestUser::query()->create([
            'email'       => self::OTP_RECIPIENT,
            'mfa_enabled' => true,
        ]);

        $factor                       = new FactorModel;
        $factor->driver               = 'email';
        $factor->recipient            = self::OTP_RECIPIENT;
        $factor->authenticatable_type = $user->getMorphClass();
        $factor->authenticatable_id   = (string) $user->id;

        // Wrap save in a subclass-aware persist via the trait's hook.
        $factor->save();

        return $factor;
    }

    /**
     * Build a non-Eloquent `Factor` stub — enough surface for the
     * abstract driver to reject it through `UnsupportedFactorException`.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    protected function makeNonEloquentFactor(): Factor
    {
        return new class extends AbstractFactorStub {};
    }

    /**
     * Build a non-Eloquent `Factor` stub returning the supplied code
     * and expiry so the `verify()` branches can be exercised without
     * touching the database.
     *
     * @param  ?string  $code
     * @param  ?\Carbon\CarbonInterface  $expires
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    protected function makeStubFactor(#[\SensitiveParameter] ?string $code, ?CarbonInterface $expires): Factor
    {
        return new class ($code, $expires) extends AbstractFactorStub {
            /**
             * Capture the seeded code / expiry pair.
             *
             * @param  ?string  $code
             * @param  ?\Carbon\CarbonInterface  $expires
             * @return void
             */
            public function __construct(
                private readonly ?string $code,
                private readonly ?CarbonInterface $expires,
            ) {}

            /**
             * @return ?string
             */
            public function getCode(): ?string
            {
                return $this->code;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getExpiresAt(): ?CarbonInterface
            {
                return $this->expires;
            }
        };
    }
}
