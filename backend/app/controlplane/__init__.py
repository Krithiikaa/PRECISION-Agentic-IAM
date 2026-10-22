"""Control-plane security (Phase 4.5).

    DATA PLANE      agent -> AEM -> tool -> resource
    CONTROL PLANE   principal -> authentication -> authorization -> ANS/PDP/PAP

The data plane asks "may this agent read this record?". The control plane asks
"may this principal change how that question gets answered?". They are kept
apart deliberately: they have different principals, different sensitivity, and
different policy, and conflating them would mean a credential granting data
access could accumulate into authority over the decision machinery.
"""
