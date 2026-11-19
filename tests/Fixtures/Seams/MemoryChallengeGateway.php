<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Keeps its challenges in memory, keyed by the binding parts it is told to
 * check and by the caller unless told not to, so the challenge gateway kit can
 * be shown one that checks too little.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MemoryChallengeGateway implements ChallengeGateway
{
    /** @var string Every challenge's code. */
    public const string CODE = '123456';

    /** @var list<string> */
    public const array EVERY_PART = ['identity_type', 'identity_key', 'application', 'session_id', 'purpose'];

    /** @var array<string, array{key: array<string, string>, caller: ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable, attempts: int, used: bool}> */
    private array $challenges = [];

    /**
     * @param  list<string>  $keyedBy
     * @param  ?int  $maxAttempts
     * @param  bool  $checksCaller
     */
    public function __construct(

        /** The binding parts a challenge answers only its own of. */
        private readonly array $keyedBy = self::EVERY_PART,

        /** Wrong codes a challenge takes, or `null` for no limit. */
        private readonly ?int $maxAttempts = 5,

        /** Whether a challenge answers only the caller it was sent to. */
        private readonly bool $checksCaller = true,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     */
    #[\Override]
    public function send(CallerContext $caller, Factor $factor, ProofBinding $binding): SendResult
    {
        $id = 'memory-challenge-' . count($this->challenges);

        $this->challenges[$id] = ['key' => $this->keyOf($binding), 'caller' => $caller->identity, 'attempts' => 0, 'used' => false];

        return SendResult::sent($id, CarbonImmutable::now()->addMinutes(5));
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome
     */
    #[\Override]
    public function verify(CallerContext $caller, Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): ChallengeOutcome
    {
        $challenge = $this->challenges[$challengeId] ?? null;

        if ($challenge === null || $challenge['key'] !== $this->keyOf($binding) || ($this->checksCaller && $challenge['caller'] !== $caller->identity)) {
            return ChallengeOutcome::refused(FailureReason::NOT_FOUND, 'No such challenge.');
        }

        if ($challenge['used']) {
            return ChallengeOutcome::failed(FailureReason::REPLAYED, 'Used.');
        }

        if ($this->maxAttempts !== null && $challenge['attempts'] >= $this->maxAttempts) {
            return ChallengeOutcome::failed(FailureReason::EXPIRED, 'Out of attempts.');
        }

        if ($code !== self::CODE) {
            $this->challenges[$challengeId]['attempts']++;

            return ChallengeOutcome::failed(FailureReason::INVALID_CODE, 'Wrong code.');
        }

        $this->challenges[$challengeId]['used'] = true;

        return ChallengeOutcome::passed();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return array<string, string>
     */
    private function keyOf(ProofBinding $binding): array
    {
        return array_intersect_key($binding->toArray(), array_flip($this->keyedBy));
    }
}
