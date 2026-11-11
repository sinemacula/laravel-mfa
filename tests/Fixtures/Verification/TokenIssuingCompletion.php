<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Verification;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Cookie\QueueingFactory;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Records the proof and issues tokens inside the transaction, as an
 * authentication layer does, queueing the refresh cookie only after commit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TokenIssuingCompletion implements PendingCompletion, StepUp
{
    /** @var string */
    public const string ACCESS_TOKEN = 'issued-access-token';

    /** @var string */
    public const string COOKIE = 'refresh_credential';

    /** @var string */
    public const string COOKIE_VALUE = 'issued-refresh-credential';

    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion  $store
     */
    public function __construct(

        /** Resolves the cookie jar. */
        private Container $container,

        /** Records the proof. */
        private ProofStoreCompletion $store,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \Tests\Fixtures\Verification\IssuedTokens
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function complete(CallerContext $caller, VerificationResult $result): IssuedTokens
    {
        $this->store->complete($caller, $result);

        return $this->issued();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \Tests\Fixtures\Verification\IssuedTokens
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function stepUp(CallerContext $caller, VerificationResult $result): IssuedTokens
    {
        $this->store->stepUp($caller, $result);

        return $this->issued();
    }

    /**
     * @return \Tests\Fixtures\Verification\IssuedTokens
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function issued(): IssuedTokens
    {
        AfterStorageCommit::run($this->container, function (): void {
            $this->container->make(QueueingFactory::class)->queue(self::COOKIE, self::COOKIE_VALUE, 10);
        });

        return new IssuedTokens(self::ACCESS_TOKEN);
    }
}
