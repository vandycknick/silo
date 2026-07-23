# Writing Architecture Decision Records

Architecture Decision Records explain what Silo decided, why the decision is
sound, what it requires, and where its boundary ends. They preserve reasoning
that code and issue history cannot express on their own.

Write for an engineer who did not participate in the original discussion. That
reader should be able to understand the problem, implement the determination,
recognize its tradeoffs, and tell which adjacent questions remain open.

This guide defines a common structure and voice. It is not a mandatory template.
A small local decision may need only the problem, decision, consequences, and
alternatives. A cross-cutting decision may need detailed contracts, migration,
security, failure semantics, and conformance requirements.

## Principles

### Record A Decision

An ADR is a decision record, not a chronology of research. Introduce the
problem, state the determination, and use the remaining sections to make that
determination precise and defensible.

The reader should not need to reconstruct the decision from implementation
details or rejected alternatives. State it early and directly.

### Explain The Reasoning

Record the constraints that made the decision necessary, the viable
alternatives, and the reasons the selected approach wins. Include measurements,
specifications, or primary references when the reasoning depends on external
facts.

Do not present a preference as inevitable. If another approach was viable,
describe its benefits before explaining why its costs are unacceptable here.

### Make Commitments Testable

Prefer requirements that an implementation or conformance test can observe.
Name paths, ownership, precedence, limits, states, failure behavior, and trust
boundaries where they are part of the decision.

Good:

> The resolver rejects a relative `SILO_RUNTIME_DIR`.

Bad:

> Runtime discovery handles invalid configuration safely.

### Separate Kinds Of Statements

Keep these categories distinct:

- adopted requirements;
- explanatory rationale;
- illustrative examples;
- accepted limitations;
- open questions;
- future work; and
- concerns that require another ADR.

Label non-normative examples and possible future APIs. An accepted ADR must not
hide an unresolved part of its core decision in an Open Questions section.

### Expose Ownership And Boundaries

Name the component, process, or package responsible for each behavior. State
what crosses a boundary and what deliberately does not.

For a multi-component decision, include a responsibility table or give each
component its own subsection. For a lifecycle decision, show the representative
flow before defining its individual steps.

### Treat Failure And Operations As Architecture

Security, migration, diagnostics, resource limits, upgrade behavior, and
partial failure are architectural concerns when the decision affects them. Do
not relegate them to implementation notes merely because they happen off the
successful path.

### Match Depth To The Decision

Depth should follow the decision's blast radius and reversibility. A package
layout shared by product installers and language SDKs deserves more detail than
a private helper name. More detail is useful only when it clarifies a contract,
rationale, consequence, or boundary.

## Document Structure

### Metadata

Every ADR begins with:

```md
# <number>. <Specific decision title>

Date: YYYY-MM-DD

Updated: YYYY-MM-DD

## Status

<one lifecycle state from the ADR index>
```

Include `Updated` only after a material revision. Use the lifecycle states from
the ADR index exactly.

### Core Sections

Every ADR requires `The Problem` or `Context`, `Decision` or `Determination`,
and `Consequences`. New and substantially revised records include
`Alternatives Considered` when another approach was viable. Add decision details
and explicit non-decisions when the summary alone does not define the complete
boundary.

#### The Problem

Describe the present constraint, the affected users or components, and why the
existing behavior is insufficient. Establish the decision boundary. A reader
should understand what question the ADR answers before encountering the answer.

#### Decision Or Determination

State the selected direction in a few paragraphs or a short list of core
invariants. Use `Decision` for consistency with the original ADR format and
`Determination` when the surrounding ADRs use that term. Do not use both for the
same summary.

The summary should be complete enough that a reader can accurately describe the
architecture without reading every implementation detail.

#### Decision Details

When the decision needs further specification, use domain-specific sections to
make it implementable. Organize these sections around reader tasks and
architectural boundaries, not around the order in which facts were discovered.

#### Consequences

Separate benefits from tradeoffs. A decision that lists only benefits has not
described its consequences.

#### Alternatives Considered

Give each meaningful alternative a descriptive heading. Explain the useful
property it offers and the concrete reason it loses under Silo's constraints.

#### What This Does Not Decide

For a decision with adjacent unresolved concerns, identify what deliberately
remains outside its boundary. Say when those concerns require another ADR rather
than merely more implementation work.

### Optional Sections

Use these sections when the decision needs them:

- `Terminology` for recurring terms that would otherwise be overloaded;
- `Goals` and `Non-Goals` for product or roadmap decisions;
- a representative flow or diagram when order and ownership matter;
- `Responsibilities` when several components implement one decision;
- compatibility and migration for persisted state, installed paths, wire
  formats, or public interfaces;
- security and trust boundaries when the decision changes authority or data
  exposure;
- failure semantics and diagnostics for runtime behavior;
- conformance requirements or release gates for contracts that must be
  qualified across implementations;
- `Accepted Limitations` for deliberate capability gaps;
- `Open Questions` for unresolved matters that do not weaken the determination;
- `Implementation References` for relevant source paths and commands; and
- `External References` for specifications and primary documentation.

### Large ADRs

A large implementation ADR will often use this order:

```md
## The Problem
## Terminology
## Representative Flow
## Decision
### Core Invariants
## Responsibilities
## Primary Contract
## Compatibility And Migration
## Security And Trust
## Failure Semantics And Diagnostics
## Conformance Requirements
## Consequences
### Benefits
### Tradeoffs
## Alternatives Considered
## Accepted Limitations
## Open Questions
## What This Does Not Decide
## Implementation References
## External References
```

Use only the sections that help explain the decision. Do not add empty
ceremonial sections.

## Tone And Prose

Write in a calm, direct, technically precise voice. The prose should be
confident without becoming promotional, candid about costs, and considerate of
the reader's time.

### Desired Voice

Use plain language, concrete subjects, active verbs, and observable behavior.

- Name the component: "`libvm` resolves the runtime root."
- Name the rule: "The resolver rejects relative paths."
- Name the consequence: "A failed replacement leaves the prior artifact
  intact."

Do not substitute approval words for technical claims. Terms such as `clean`,
`robust`, `modern`, `seamless`, `flexible`, and `secure` rarely explain what the
system does. State the property that would justify the adjective.

Good:

> `libvm` resolves one complete runtime component set and retains it for the
> lifetime of `Runtime`.

Bad:

> `libvm` provides a robust and seamless runtime-discovery experience.

Good:

> The package never writes into `Silo.app`; machine state is user-owned.

Bad:

> The application bundle is kept clean and safe.

### Perspective And Pronouns

Prefer the system or responsible component as the grammatical subject. This
keeps ownership visible and prevents a decision from sounding aspirational.

Use `Silo` for product-wide commitments and a component name for implementation
responsibilities. `We` is appropriate when describing a design need or
reasoning through a tradeoff, but should be rare in normative sections. Address
the reader as `you` only in a user-facing example.

Good:

> Silo packages the helpers and default assets as one co-versioned runtime
> payload.

Good:

> `libvm` never downloads a runtime during `Runtime::open`.

Bad:

> We will try to make sure everything finds the right runtime.

### Confidence And Uncertainty

Use present tense for accepted architecture, even when implementation remains
pending. Be decisive about requirements and explicit about uncertainty.

Use `future work`, `open question`, `possible design`, or `non-normative
example` only when those labels are accurate. Do not weaken a requirement with
`generally`, `usually`, `ideally`, or `should` when the document means `must`.

Good:

> The initial Linux runtime requires glibc 2.39. Raising that floor changes the
> support matrix and requires an ADR update.

Bad:

> The runtime will ideally use a reasonably current glibc version.

A contract for a future transport may still be normative:

> A future Go SDK uses an explicit installation API. It does not download a
> runtime during import, runtime opening, or VM start.

### Technical Explanation

Explain a mechanism in the order a reader needs to understand it:

1. State the invariant or decision.
2. Identify the responsible component.
3. Describe the flow or data boundary.
4. State relevant failure behavior and limits.
5. Explain the rationale or consequence.

Put a representative flow before a large set of component rules. Use diagrams,
layouts, and examples to clarify a rule, not to replace it.

Good:

> `libvm` creates the composite initramfs in a temporary file in the destination
> directory. It atomically renames the file only after writing and closing the
> complete artifact. A failed write cannot expose a partial composite as a
> launch input.

Bad:

> We atomically create a temporary composite initramfs, which is safer.

Prefer a concrete boundary over a vague abstraction.

Good:

> `vmmon` receives the resolved VM specification. It does not resolve agent
> assets, serialize `AgentConfig`, or write CPIO entries.

Bad:

> `vmmon` remains appropriately decoupled from boot concerns.

### Rhythm And Paragraphs

Use short-to-medium sentences and compact paragraphs. A paragraph should make
one principal claim, then explain its consequence, exception, or rationale.
Start a new paragraph when the subject, time frame, or kind of statement
changes.

Vary sentence length naturally. Dense technical material may require a long
sentence, but each sentence should still have one primary predicate. Do not use
fragments merely to manufacture emphasis.

Introduce a list or table with a brief sentence. When order, precedence, or
normativity matters, explain how to read it.

### Transitions

Use transitions when they express a logical relationship:

- `Therefore` introduces a consequence.
- `However` introduces a real contrast.
- `For example` introduces an illustration.
- `In contrast` compares alternatives.
- `This ADR does not decide` marks an intentional boundary.

Do not use `Additionally`, `Furthermore`, or `Moreover` merely to join unrelated
facts. Avoid `obviously`, `clearly`, `just`, and `simply`; explain the point or
omit the qualifier.

Good:

> The default assets are architecture-specific. Therefore package-owned assets
> live below a private library directory rather than an architecture-neutral
> shared-data directory.

Bad:

> Obviously, the assets are architecture-specific. Furthermore, they go in a
> private directory.

### Humor And Personality

An ADR may sound human, but its job is clarity rather than performance. Avoid
sarcasm, snark, slogans, jokes at a user's expense, and references that will age
poorly.

A small amount of dry personality is acceptable in explanatory prose when it
does not obscure a requirement. If removing a line makes the contract clearer,
remove it.

### Rhetorical Questions

Use rhetorical questions sparingly. One may frame a genuine design tension in
the problem statement when the answer follows immediately. Prefer a direct
statement everywhere else.

Do not use rhetorical questions in decision, security, migration, failure, or
conformance sections.

### Normative Language

Use these terms consistently:

| Term | Meaning |
| --- | --- |
| `must` | Required for correctness, compatibility, safety, or conformance. |
| `must not` | Prohibited behavior. |
| `may` | Allowed variation. |
| `does not` | Deliberate exclusion. |
| `can` | Capability, not permission. |
| `should` | Advice rather than a requirement; use rarely in an ADR. |

State the actor and condition with each requirement.

Good:

> A portable runtime root must contain every required helper and asset. The
> resolver rejects a root with a missing or non-regular component.

Bad:

> Runtime roots should be complete.

### Wording To Avoid

| Avoid | Prefer |
| --- | --- |
| `robust`, `seamless`, `clean`, `simple`, `easy` | The concrete property or mechanism. |
| `obviously`, `clearly`, `just`, `simply` | An explanation, or nothing. |
| `best practice` | The specific practice and why it fits Silo. |
| `we should`, `it would be nice to` | `Silo does`, `Silo must`, or an open question. |
| `supports` when behavior is vague | `accepts`, `resolves`, `installs`, `rejects`, or `starts`. |
| `handles` | The exact error, operation, or state transition. |
| `etc.` | The complete relevant set or an explicit scope boundary. |
| `future-proof` | The extension point or compatibility guarantee. |
| `magic` | The discovery, validation, or generation mechanism. |
| `helpful error` | The diagnostic information the error contains. |

## Lists, Tables, And Examples

Use numbered lists for precedence, ordered execution, lifecycle transitions, or
checklists. Use bullets for unordered invariants, alternatives, benefits,
tradeoffs, and limitations. Keep sibling items grammatically parallel.

Use tables for finite comparisons, responsibility assignments, state matrices,
fixed layouts, and bounded values. Do not put an extended argument in a table
cell.

Use fenced blocks only for literal artifacts such as commands, API payloads,
source snippets, filesystem layouts, and diagrams. Specify a language when one
exists. State the rule in prose before showing its representation.

Label a sketch when it is not a contract:

```md
This is a non-normative example. Exact fields remain outside this ADR.
```

For a filesystem or package layout, explain ownership, mutability, permissions,
and resolution behavior in prose. A tree alone does not define those semantics.

## Consequences And Alternatives

Consequences explain what becomes better and what becomes harder because of the
decision. Use `Benefits` and `Tradeoffs` subsections for decisions with several
effects. Include operational and organizational costs where they are material.

Alternatives should be credible. Describe enough of each alternative for a
future reader to understand why it was tempting, then reject it using the
decision's actual constraints. Avoid dismissive phrases such as "too complex"
without naming the complexity and who would own it.

## Limits, Questions, And Future Work

An accepted limitation is a known property of the selected design. An open
question is unresolved but does not prevent adoption. Deferred implementation
is work required to deliver the decision. A non-decision belongs to an adjacent
design and may require another ADR.

Keep these categories separate. This prevents a future reader from mistaking a
deliberate boundary for forgotten work or an implementation task for an
unsettled architecture.

## Review Checklist

Before proposing an ADR, verify that:

- the problem is understandable without knowing the proposed solution;
- the decision appears early and can be summarized accurately;
- normative statements name their responsible actor;
- requirements, examples, future work, and open questions are distinguishable;
- ordered behavior has one canonical list;
- repeated terms have one meaning;
- failure, migration, security, and diagnostics are covered where relevant;
- benefits and tradeoffs are both explicit;
- viable alternatives receive concrete rejection reasons;
- accepted limitations and non-decisions are easy to find;
- external claims use primary references where practical;
- examples agree with the prose contract;
- vague adjectives have been replaced with observable properties; and
- every paragraph helps explain the decision, its reasoning, or its boundary.
