"""Phase 7 - secure agent-to-agent transactions.

    envelope.py      what a transaction IS, and how it is verified
    service.py       the ledger: verify, register exactly once, reconcile, record
    client.py        building and signing one, from the sender's side
    presentation.py  what a human is shown when a payment escalates

THE ONE SENTENCE THIS PACKAGE EXISTS TO ENFORCE:

    A VALID A2A SIGNATURE IS NOT AUTHORIZATION.

Every transaction reaches the PDP. Nothing here decides whether an action is
permitted, and there is no threshold, role check or allow-list in any file in
this package -- a test greps for them.
"""
