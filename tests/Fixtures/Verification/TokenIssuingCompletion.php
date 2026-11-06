<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Verification;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Cookie\QueueingFactory;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * A completion that behaves as an authentication layer's does: the proof is
 * recorded, tokens are issued and returned from inside the transaction, and the
 * refresh cookie is queued only once the storage connection commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TokenIssuingCompletion implements PendingCompletion, StepUp
{
    /** @var string The access token every completion issues. */
    public const string ACCESS_TOKEN = 'issued-access-token';

    /** @var string The name of the refresh cookie. */
    public const string COOKIE = 'refresh_credential';

    /** @var string The value of the refresh cookie. */
    public const string COOKIE_VALUE = 'issued-refresh-credential';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion  $store
     */
    public function __construct(

        /** The container the cookie jar is resolved from. */
        private Container $container,

        /** What records the proof. */
        private ProofStoreCompletion $store,
    ) {}

    /**
     * Complete the pending session and issue its tokens.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \Tests\Fixtures\Verification\IssuedTokens
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function complete(PendingContext $pending, VerificationResult $result): IssuedTokens
    {
        $this->store->complete($pending, $result);

        return $this->issued();
    }

    /**
     * Step the active session up and issue its token.
     *
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
     * Issue the tokens, and queue the cookie once the transaction commits.
     *
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
