"""Phase 6: Just-In-Time temporary access.

A JIT grant is an INPUT to authorization, never a substitute for one. It
carries an expensive precondition -- a human decision -- forward across a
bounded window; every use is still decided by the PDP with every ordinary rule
running. See `app/jit/grant.py` for why that framing is load-bearing rather
than cautious.
"""
