# Policy repository (PAP)

Real Rego, evaluated by a real OPA runtime. The PAP reads this directory and
pushes each module into OPA through its Policy API; `manifest.json` carries the
lifecycle metadata (id, version, owner, purpose, scope, status) that a `.rego`
file cannot express.

OPA is 1.x, so every module here is **Rego v1**: `if` on rule bodies and
`contains` for partial sets are mandatory.

```
policies/
  manifest.json          policy identity and lifecycle -- bump `version` on any rule change
  decision.rego          DATA PLANE: combining algorithm + shared credential helpers
  loan/
    credit.rego          permit credit_records for credit_analysis / loan_assessment
    resource_scope.rego  deny any resource a valid credential does not name
  security/
    credential_state.rego  translate the Phase 2 verifier's verdict into a decision
    sensitive.rego         route sensitive actions to HUMAN_APPROVAL_REQUIRED
  control_plane/
    decision.rego          CONTROL PLANE: its own combining algorithm + principal helpers
    agent_self.rego        an agent may act on ITSELF, and nothing else
    administration.rego    each administrative operation -> the one role it requires
```

## Two packages, deliberately

`agentic_iam.authz` answers *"may this agent read this record?"*.
`agentic_iam.control_plane` answers *"may this principal change how that gets
decided?"*.

They are separate packages with separate combining algorithms so that hardening
the control plane cannot alter resource-authorization semantics, and so no
data-plane rule has to be re-read for control-plane inputs it was never written
for. Both are deny-overrides and default-deny, and both seed their partial sets
empty so that removing every policy fails **closed** rather than failing to
compile.

## Rules

**Authorization logic belongs here, as Rego.** It must not be reimplemented as
Python `if` statements in the AEM or the control-plane guard: the AEM enforces,
the guard authenticates, the PDP asks, and OPA decides. Two implementations of
one security decision will eventually disagree, and will do so silently. Tests
assert that no privilege rule appears in `app/controlplane/guard.py` or
`app/controlplane/authenticator.py`.

**Rego never re-checks cryptography.** `input.pip.credentials[_].valid` is the
Phase 2 verifier's verdict, and `input.principal` exists only because the
control-plane authenticator already proved control of that DID. Policy consumes
those verdicts; it does not re-derive them.

**No policy names an agent DID.** Decisions are a function of subject, action,
resource, purpose and credential state — never `agent == X`.

**When several rules deny at once**, the reported reason is chosen by a
deterministic sort. Every denial in the set is individually correct; the sort
only decides which is *reported*. Guard rules that would otherwise both fire on
the same input, so the reported reason is the most diagnostic one — see the
`subject_resolved` guard in `security/credential_state.rego` and the
`principal_is_administrator` guard in `control_plane/administration.rego`.

## Changing policy

Never by hand against OPA — its admin API is bound to loopback and is not the
supported path. Edit the `.rego` file, bump `version` in `manifest.json`, then:

```
POST /api/v1/policies/reload          # requires the `policy_admin` role
```

The version is written onto every decision the policy produces, so an audit row
identifies exactly which revision of which policy decided.
