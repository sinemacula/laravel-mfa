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

    /** Keeps a proof of the current sign-in bound to another identity. */
    case ACCEPTS_ANY_IDENTITY;

    /** Keeps a proof of the current sign-in's id bound to another application. */
    case ACCEPTS_ANY_APPLICATION;

    /** Reads the current sign-in's proofs for whichever sign-in is named. */
    case READS_ANY_SIGN_IN;

    /** Keeps a proof of another sign-in, though it refuses it. */
    case KEEPS_A_REFUSED_PROOF;

    /** Judges a proof by the identity its binding names, not the one it is recorded for. */
    case KEYS_BY_BINDING;

    /** Forgets the current sign-in and its proofs before it throws a refusal. */
    case DESTROYS_ON_REFUSAL;

    /** Keeps a refused proof for the identity its binding names. */
    case KEEPS_FOR_THE_NAMED_IDENTITY;

    /** Ends the sign-in of the identity a refused proof's binding names. */
    case ENDS_THE_NAMED_SIGN_IN;

    /** Still reads the proofs of a sign-in it has since replaced. */
    case RETAINS_SIGN_INS;

    /** Accepts a proof of the current sign-in and keeps none. */
    case DROPS_PROOFS;

    /** Keeps the sign-in current when it is forgotten. */
    case KEEPS_SESSION;

    /** Keeps the proofs, still read for it, when the sign-in is forgotten. */
    case KEEPS_PROOFS;
}
