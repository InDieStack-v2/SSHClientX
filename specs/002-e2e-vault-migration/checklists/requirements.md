# Specification Quality Checklist: End-to-End Encrypted Vault Migration

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-09-06
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)
- [x] All acceptance scenarios are defined
- [x] Edge cases are identified
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria
- [x] User scenarios cover primary flows
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification

## Notes

**Iteration 1 findings, all fixed in the spec:**

1. *No implementation details* — the source description was written in implementation
   terms (`SSHCLTX1`, XChaCha20-Poly1305, Argon2id, `kid`, `BOX_*` / `VAULT_*` codes,
   libsecret/DPAPI/Keychain, `verify_and_import`). Those were moved out of the
   requirements and restated as observable behaviour ("a stable 128-bit key identifier",
   "the operating system's own secure store", "its own outcome"). The concrete names
   stay in `docs/features/spec-00-e2e-vault.md` and `spec-01-export-import.md`, which
   `/speckit-plan` will bind to.
2. *Technology-agnostic success criteria* — first-pass SC referenced header fields and
   algorithm names; rewritten as user- and tester-observable outcomes.
3. *Scope bounded* — the four "must be in scope" items from the request are each
   resolved rather than restated: migration is US1/FR-013–018, the cross-device break is
   US2/FR-019–022, restore-over-existing is decided *yes* (FR-032/033), and Android creates
   and imports sealed vaults while legacy migration remains desktop-only (FR-038–FR-042).

**Iteration 2 — open questions resolved by the user (2026-09-06):**

- **D1**: password stays as the login credential, decoupled from vault-key derivation.
  Specified as a genuine two-of-two factor (secure store AND password) rather than a UI
  gate, because an inert gate would be weaker than what ships today. Added FR-007,
  FR-007a, FR-007b, SC-011; noted as an intentional deviation from spec-00 §3, which
  treats passphrase and device unlock as alternatives.
- **D2**: desktop and Android create and import sealed vaults; Android opens, uses, and saves
  a new-format vault whose key arrived via the recovery kit, but cannot migrate a legacy vault.
  FR-038–FR-042 and SC-012 cover the platform boundary. The Android recovery-kit restore
  remains a convenient single action; a recovered unclaimed key can instead be matched through
  general import.

**Blocking item outside the checklist:**

- **Constitutional Prerequisites** is a hard gate. Four rules in constitution v2.0.0
  forbid this feature; a MAJOR amendment is required before implementation. The spec is
  valid but not actionable until then. D2 changes the shape of the Android conflict
  (parity is broken by capability rather than by format) but does not remove it.
