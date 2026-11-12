# Identity

User authentication, authorization, and lifecycle management.

## Specs

```
authentication.md              Session/JWT and credential validation
├── sso-authentication.md      OIDC SSO login flow (deferred)
└── local-authentication.md    Username/password login, lockout

api-key-management.md          API key lifecycle, REST API, and CLI
api-key-service.md             API key mutation and query service
identity-provisioning.md       External provisioning, role mapping (deferred)
user-service.md                Service-layer contract for user mutations
user-management.md             Admin CLI and API for user operations
user-avatars.md                User picture URLs and the Slack fetcher
rbac.md                        Role definitions and endpoint permission map
identity-audit-log.md          Identity audit trail (IdentityAuditEvent)
```

## Relationships

- `authentication.md` is the parent spec for SSO and local login. It also
  validates API keys as credentials; `api-key-management.md` owns their
  lifecycle and consumer surfaces, and `api-key-service.md` owns database
  operations.
- `identity-provisioning.md` (deferred) defines how external users are
  provisioned and how group memberships map to roles; `rbac.md` defines
  what those roles grant.
- `user-service.md` is the centralized service contract consumed by
  `user-management.md`, `identity-provisioning.md`, and any future
  entry point that mutates users.
- `user-avatars.md` owns the picture URL of every user representation and the
  fetcher that looks it up in Slack; `user-service.md` clears the URL on
  deactivation, on a change of email, and when a user becomes a bot account.
