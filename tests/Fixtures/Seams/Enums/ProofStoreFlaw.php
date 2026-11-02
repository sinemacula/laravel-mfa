<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams\Enums;

/**
 * The one flaw a `FlawedProofStore` has, so each of the proof store kit's
 * checks can be shown to reject a store that breaks it alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum ProofStoreFlaw
{
    /** Names another sign-in as the current one once one is begun. */
    case WRONG_SESSION;

    /** Refuses nothing it is given, once a sign-in is begun. */
    case ACCEPTS_ANY_SIGN_IN;

    /** Accepts a proof of the current sign-in and keeps none. */
    case DROPS_PROOFS;

    /** Keeps the sign-in current when it is forgotten. */
    case KEEPS_SESSION;

    /** Keeps the proofs when the sign-in is forgotten. */
    case KEEPS_PROOFS;
}
