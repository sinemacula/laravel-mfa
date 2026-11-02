# Stable Names

## Purpose

This note records which names the package treats as stable once released, where each is documented, and how the test
suite holds the documentation to the code, so an application, an audit pipeline or an authentication layer can rely on
a name without reading the source.

## Invariants

- The stable names are the values of every backed enum in `src/Enums` (the failure reasons of `FailureReason` and the
  requirement parts of `RequirementPart` among them, which an application words for itself), the event class names, the
  keys of an event's context (`Events\EventContext::KEYS`), the keys the package contributes to the authentication
  context (`Context\AuthenticationContextContributor`), every configuration key of `config/mfa.php`, every key of an
  application's block (`Applications\ApplicationBlock`), and the methods of the `mfa` manager.
- Each is documented in the README or a guide in `docs/guides`, in code type: the enum values in the vocabulary table of
  [Assurance](../guides/assurance.md), and the failure reasons again in the outcomes of
  [Verification](../guides/verification.md); each event as a row of the table in [Events](../guides/events.md), keyed
  by its short name, with its context keys below it; the authentication context keys in
  [Middleware](../guides/middleware.md); every configuration key by its full dotted path, and every application key by
  its path within the block, in [Configuration](../guides/configuration.md); and every manager method shown being
  called, mostly in [Helpers](../guides/helpers.md).
- Names are code, so American (`enrollment`, `confirmed_per_type`); the prose around them is British.
- The names change freely until the first release. After it, a rename or removal is a change to every application that
  stores, logs, maps or words the name.

## Success Path

- A new name (an enum case, an event, a context key, a configuration or application key, a manager method) lands with
  its documentation in the same change. `DocumentationTest` finds the new name from the code itself (every enum in
  `src/Enums`, every event in `src/Events`, the context keys, the configuration file, the application block's keys and
  the manager's methods) and fails until the documentation names it.
- Every `Mfa::` call the documentation shows is checked to exist on the manager or the facade, so an example cannot keep
  a method that was renamed.

## Failure / Edge Cases

- The test catches an omission or a rename, not wrong prose: it checks that each name appears, in code type, somewhere
  in the README or the guides, not that what is said about it is right. That is held by review.
- An enum value that is a common word can be matched by an unrelated mention in code type. The guides name each value
  where it is described, so the check is a backstop, not a proof.
- The manager's `__call()` and `setContainer()` only refuse, so they are not required to be documented as calls.
- The authentication context keys are read from the contributor's answer with nobody signed in. Its neutral answer has
  the same keys as a full one: the contributor's return type states them, and its own tests compare whole answers.

## Implementation Anchors

- `src/Enums/`: the enums whose values are stable.
- `src/Events/`, `src/Events/EventContext.php`: the events and the context keys.
- `src/Context/AuthenticationContextContributor.php`: the authentication context keys.
- `config/mfa.php`, `src/Applications/ApplicationBlock.php`: the configuration and application keys.
- `src/MfaManager.php`, `src/Facades/Mfa.php`: the manager's methods and the facade.

## Authoritative Tests

- `tests/Unit/Documentation/DocumentationTest.php` `testEveryEnumValueIsDocumented`,
  `testEveryEventIsInTheEventsTable`, `testEveryEventContextKeyIsDocumented`,
  `testEveryAuthenticationContextKeyIsDocumented`, `testEveryConfigurationKeyIsDocumented`,
  `testEveryApplicationKeyIsDocumented`, `testEveryManagerMethodIsDocumented`,
  `testEveryMfaCallTheDocumentationShowsExists`
- `tests/Unit/Enums/`: each enum's values pinned one by one.
- `tests/Unit/Events/EventCatalogTest.php`: each event's payload.

## Change Triggers

Update this note when any of the following change:

- a kind of name becomes stable, or stops being one
- where a kind of name is documented, or the documentation the test reads (the README and `docs/guides`)
- a configuration key holding data the application names (a map whose keys are its own) rather than settings, which
  the test would then read as a whole rather than key by key
