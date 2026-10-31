# Platform Version

## Purpose

Lets an API client learn which Sentinel version serves it. Users state that
version when they report a problem, together with the request ID of the
failing request (`docs/api-spec.md`, Request Tracing), and a client can
compare it with the versions that it supports (`docs/deployment.md`, Consumer
Compatibility). A client cannot derive the version from the version that it
was built against: a host can run any later release that the client
supports.

The CLI prints the same version with `sentinel --version`
(`docs/cli-reference.md`). Over HTTP, the only other source is `info.version`
of the OpenAPI document (`docs/api-spec.md`, OpenAPI Document and Interactive
Documentation), which is not an operation and which a client generated from
that document does not read.

## API Endpoints

### Get Platform Version

Returns the platform version of the Sentinel process that serves the request.

```text
GET /api/v1/version
```

**`Access: Authenticated`**

**Request body**: none.

**Query parameters**: none.

**Response** (200):

```json
{
  "data": {
    "version": "0.13.1"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `version` | string, required | The platform version (`docs/deployment.md`, Platform Version and Source of Truth) of the process that serves the request, in the form `<major>.<minor>.<patch>`: the version of its release tag without the `v` prefix |

`version` names the platform version, not the API version, which is the `v1`
of the path (`docs/api-spec.md`, Versioning).

**Behavior**:

- The value equals `info.version` of the OpenAPI document that the same
  process serves at `/api/openapi.json`. The image of a release therefore
  returns the version of that release, which its published OpenAPI document
  carries too (`docs/deployment.md`, API Documentation Publication).
- The value is the same for every caller and does not change during the life
  of the process.
- Each process returns its own version. While a host is upgraded, processes of
  two versions can serve it, so two requests can return different values.
- An image built from a commit that no release contains returns the version
  set by the latest Release PR merged before that commit (`docs/deployment.md`,
  Platform Version and Source of Truth). Only a release image is identified by
  the value.
- Beyond authentication, whose effects and dependencies are its own
  (`docs/features/identity/authentication.md`, Authentication Dependencies),
  the operation has no effect, reads no application data, and uses no
  dependency.

**Error responses**: none specific to this endpoint.

Implementation note: the version is process metadata, not application data.
The route reads it from the FastAPI application, which `backend/app/main.py`
creates with the version of the installed `sentinel` package and which
publishes it as `info.version`. No service or database operation is
involved beyond authentication (`docs/architecture.md`, Backend Layer
Architecture).

## Design Decisions

- **A dedicated operation.** The version is not a field of
  `GET /api/v1/users/me`, whose response is the user's own profile and which
  the user directory mirrors (`docs/features/identity/user-management.md`,
  Get User). It is not a response header either: a client generated from the
  OpenAPI document does not type headers, and a header would appear on every
  response, unauthenticated ones included. The probes stay outside the
  domain API and expose no versions
  (`docs/features/platform/health-endpoints.md`, Design Decisions).
- **`Access: Authenticated`.** Reading the version neither bootstraps
  authentication nor serves infrastructure that does not authenticate, so it
  does not meet the Criterion for Public access
  (`docs/features/identity/rbac.md`, Access Levels). No client needs the
  version before sign-in, and automation reads it with an API key, which the
  account of the read-only profile can hold. The access level is chosen by
  that criterion, not to keep the version secret: the OpenAPI document,
  served without authentication, carries it in `info.version`, and so
  discloses to any client that reaches the API which release the host runs.
  That exposure is accepted and is not changed by this operation: even
  without `info.version`, the served document identifies the contract of the
  release, and with it the release or the patch releases that share that
  contract, against the documents published with each release, so withholding
  the version would require authenticating the document.
- **What the resource contains.** The resource is the identity of the build
  that the process runs. A field belongs to it only when it describes that
  build, is the same for every caller, does not change during the life of the
  process, and is read without a dependency beyond authentication. The
  version of a component of the build, such as the Python runtime, a library,
  or an operating-system package, does not belong to it: it serves only to
  fingerprint the host, and the SBOM of each release lists the components
  (`docs/deployment.md`, Release Supply-Chain Artifacts). A new field that
  meets this criterion is an additive change (`docs/api-spec.md`,
  Versioning). Live state and information that a client needs before sign-in
  belong to other resources, whose dependencies, failures, and access level
  differ: the probes report the readiness of a process
  (`docs/features/platform/health-endpoints.md`), the fetcher list
  reports ingestion (`docs/features/platform/fetcher-operations.md`, List
  Fetchers), the IBS consumer has its status endpoint
  (`docs/features/integrations/ibs-rabbitmq-integration.md`, Get IBS Consumer
  Status), and authentication-provider discovery, which is deferred, is
  Public (`docs/features/identity/sso-authentication.md`, List Auth
  Providers).

## Security Considerations

- The response contains only the platform version, which the OpenAPI document
  already serves without authentication. It contains no versions of
  components, such as the Python runtime, libraries, or PostgreSQL, and no
  hostnames, replica identities, configuration, or other internal topology.
- The response is identical for every authenticated caller, so it discloses
  nothing about the caller, their roles, or any resource.
- The operation adds no unauthenticated response: the probes still expose no
  versions (`docs/features/platform/health-endpoints.md`, Security
  Considerations).

## Access Control

| Action | Access |
|--------|--------|
| GET /api/v1/version | Authenticated |

## Cross-references

- `docs/api-spec.md` — Versioning; OpenAPI Document and Interactive
  Documentation; Request Tracing
- `docs/features/identity/rbac.md` — Access Levels; Endpoint Permission Map
- `docs/deployment.md` — Platform Version and Source of Truth; Consumer
  Compatibility; Version Locations; API Documentation Publication
- `docs/features/platform/health-endpoints.md` — the probes, which expose no
  versions
- `docs/cli-reference.md` — `sentinel --version`
