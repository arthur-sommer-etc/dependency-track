| Status | Date | Author(s) |
|:---|:---|:---|
| Proposed | 2026-11-11 | [@arthur-sommer-etc](https://github.com/arthur-sommer-etc) |

## Context

Human users need individual credentials for scripts. Team keys cannot identify the person making a request. Service accounts already have expiring keys backed by a user identity. A separate token format, authentication service, or database table would duplicate that machinery and increase maintenance costs.

## Decision

We will reuse the existing user-owned API key format, hashed verifier, expiry, usage tracking, and user principal. Add self-service REST API v2 endpoints and a profile menu page. Token management requires a human user's interactive session. A token cannot use these self-service endpoints to create replacement tokens. Token names are required, and expiration uses the existing API key lifetime limit.

The database resolves the owner's permissions, teams, and suspension state on every authenticated request. User-owned keys never receive extra grants from key-to-team links. Existing portfolio authorization sees the same user principal as an interactive session. Deleting a user cascades to the keys. Expiration and revocation take effect on the next request. Audit context includes the username and the non-secret public token identifier.

LDAP and OIDC tokens use the local user's current permissions. Directory membership refresh continues to happen through the existing interactive login flow. Token authentication cannot revalidate an external password or refresh identity provider claims. External account disablement alone does not immediately revoke a token. Owners can revoke their tokens through their session. Administrators can delete the local user as part of offboarding. Managed users can also be suspended locally. This change does not add an administrator endpoint to revoke another human user's tokens. The existing schema does not allow suspension of LDAP or OIDC users. We will document that limit rather than imply live directory synchronization.

We will not add narrower token scopes in this change. The existing permissions and portfolio access remain the source of authorization.

Self-service password changes also require a bearer session. Otherwise an ordinary managed-user token could change the login password and obtain a session that can issue replacement tokens. This restriction is not a narrower authorization scope: a token whose owner has access-management permissions retains administrative password-reset and credential-management capabilities.

## Consequences

No database migration or changes to team and service-account key management are needed. Secrets appear only in the creation response, with caching disabled. Existing last-used tracking is asynchronous and can lose updates under overload, so it is informational rather than an audit ledger. Existing security records include the token identifier through request logging context.

The design requires coordinated backend and frontend deployment. Documentation remains marked unreleased until a release includes the feature. Stakeholders must accept this decision before merge.
