# Spec2Core

**LLM-Assisted Specification Analysis and Resource-Authorization Testing for
5G Core Service-Based Interfaces.**

## Project overview

5G Core Network Functions communicate through HTTP APIs protected by OAuth2
access tokens and service-level scopes. Possessing the correct scope proves that
a Network Function may call a service, but does not necessarily prove that it
may access the specific UE, session, registration, subscription, or policy
selected by the request.

This project studies that distinction on two connected fronts:

1. **Specification analysis** determines which NF should be related to each
   addressed resource and which checks, if any, the 3GPP specifications require.
2. **Implementation testing** executes cross-owner requests against a live 5G
   Core and compares the observed behavior with the specification analysis.

The objective is therefore broader than finding implementation bugs. The
pipeline distinguishes between an implementation that fails to enforce an
explicit normative check and a service specification that does not clearly
define the necessary dynamic resource binding.

Spec2Core is not only a vulnerability scanner. It reconstructs a semantic
security contract that is not directly machine-readable and connects three
levels of evidence:

```text
expected resource-binding semantics
              -> specified protection
              -> implementation behavior
```

## Threat model and core question

A 5G Core deployment may contain multiple instances of the same NF type, each
with its own NF instance identity and serving different UE-, session-, or
procedure-specific contexts. Spec2Core assumes that one such instance is
compromised or malicious but remains legitimately registered and able to
obtain a valid access token for the target operation.

The attacker does not need to forge tokens or bypass the operation-level
scope. Instead, it uses otherwise valid authorization to address a resource
associated with another NF instance:

> **right NF type + right operation + right scope + wrong resource**

The central question is: even when an NF is allowed to invoke an SBI operation,
is it also authorized to act on this particular UE, registration, session,
subscription, context, or policy object?

## End-to-end architecture

```text
       3GPP OpenAPI specifications          3GPP TS procedure text
                    |                                  |
                    +----------------+-----------------+
                                     |
                                     v
                    Part A — Specification analysis
              endpoint selection and deterministic retrieval
                                     |
                         operation context packs
                                     |
                      +--------------+--------------+
                      |                             |
                      v                             v
             Expected binding agent       Existing protection agent
             Who should own/use it?        What check is specified?
                      |                             |
                      +--------------+--------------+
                                     |
                                     v
                         Authorization profiles
                    shared contract between both parts
                                     |
                                     v
                    Part B — Implementation testing
                    scenario generation + human review
                                     |
                     owner NF versus non-owner NF
                                     |
                     live request, controls and evidence
                                     |
                                     v
                  Specification-versus-runtime comparison
                                     |
                                     v
               implementation issue / specification gap /
                    protection confirmed / inconclusive
```
