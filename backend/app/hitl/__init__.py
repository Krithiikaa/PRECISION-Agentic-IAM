"""Human-in-the-Loop authorization (Phase 5).

`HUMAN_APPROVAL_REQUIRED` stopped being a decision value with nothing behind it
in this package: a real person, authenticated against a real identity provider,
sees exactly what they are approving, and their decision becomes a signed,
bound, expiring, single-use artifact that the PDP re-evaluates.

What this package does NOT do: authorize anything. The approval is evidence.
The PDP is still the authority, and the AEM is still the only thing that can
reach a protected tool.
"""
