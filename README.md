# reposilite-gitlab-oidc-auth

A [Reposilite](https://reposilite.com/) 3.5.x plugin that authenticates GitLab CI
jobs using [OIDC ID tokens](https://docs.gitlab.com/ci/secrets/id_token_authentication/).

GitLab CI pipelines present a short-lived JWT as the password via HTTP Basic
Auth. The plugin verifies the token cryptographically against the GitLab JWKS
endpoint and creates a TEMPORARY access token with route-based permissions
derived from **template tokens** stored in the Reposilite database.

## How It Works

1. GitLab CI job requests an OIDC ID token (`id_tokens` keyword, GitLab 15.7+)
2. The job authenticates to Reposilite using HTTP Basic Auth:
   - **username**: `gitlab-oidc` (configurable)
   - **password**: the OIDC JWT
3. The plugin verifies the JWT signature via the GitLab JWKS endpoint
4. The plugin looks up **template tokens** by name (derived from JWT claims)
   and unions their routes
5. A TEMPORARY access token is created with the combined routes
6. Non-CI users (any other username) pass through to the next authenticator
   (BasicAuthenticator or LDAP)

## Authorization via Template Tokens

The plugin uses Reposilite's native token system for authorization. Instead of
configuring repository permissions in `configuration.shared.json`, you create
persistent **template tokens** in the database with a naming convention. The
plugin looks up matching tokens at authentication time and clones their routes
to the ephemeral CI token.

### Naming Convention

| Token name pattern | Matched when |
| -------------------- | -------------- |
| `gitlab-ci:{namespace}` | Any CI job in the GitLab namespace (group) |
| `gitlab-ci:{project_path}` | Any CI job in the specific project |
| `gitlab-ci-protected:{namespace}` | CI job on a **protected** branch/tag in the namespace |
| `gitlab-ci-protected:{project_path}` | CI job on a **protected** branch/tag in the project |

The plugin extracts `namespace_path`, `project_path`, and `ref_protected` from
the JWT claims and looks up matching template tokens. Routes from all matching
tokens are unioned into the ephemeral token.

### Lookup Rules

**Unprotected ref** (feature branch): looks up 2 tokens

- `gitlab-ci:{namespace_path}`
- `gitlab-ci:{project_path}`

**Protected ref** (main, tags): looks up 4 tokens

- `gitlab-ci:{namespace_path}`
- `gitlab-ci:{project_path}`
- `gitlab-ci-protected:{namespace_path}`
- `gitlab-ci-protected:{project_path}`

Any token that doesn't exist is silently skipped. If no template tokens match,
the CI token is created with zero routes (authentication succeeds, but all
repository access is denied).

### Example

Given these template tokens in the database:

| Token name | Routes |
| ------------ | -------- |
| `gitlab-ci:beso` | READ on `/releases`, `/snapshots` |
| `gitlab-ci-protected:beso` | WRITE on `/releases`, `/snapshots` |
| `gitlab-ci:beso/internal-lib` | READ on `/internal-releases` |

**Feature branch build** in `beso/my-app`:

- Matches: `gitlab-ci:beso` (namespace)
- Result: READ on `/releases`, `/snapshots`

**Protected branch build** in `beso/my-app` (e.g. `main`):

- Matches: `gitlab-ci:beso` + `gitlab-ci-protected:beso`
- Result: READ + WRITE on `/releases`, `/snapshots`

**Protected branch build** in `beso/internal-lib`:

- Matches: `gitlab-ci:beso` + `gitlab-ci:beso/internal-lib` + `gitlab-ci-protected:beso`
- Result: READ on `/releases`, `/snapshots`, `/internal-releases`; WRITE on `/releases`, `/snapshots`

### Creating Template Tokens

Template tokens are regular Reposilite access tokens. Create them using the
Reposilite CLI, REST API, or web dashboard.

**Via Reposilite CLI** (in the web dashboard console):

```text
token-generate gitlab-ci:beso
token-route-add gitlab-ci:beso /releases r
token-route-add gitlab-ci:beso /snapshots r
token-generate gitlab-ci-protected:beso
token-route-add gitlab-ci-protected:beso /releases rw
token-route-add gitlab-ci-protected:beso /snapshots rw
```

**Via REST API** (using the Reposilite token API):

```bash
curl -u admin:secret -X PUT "https://maven.example.com/api/tokens/gitlab-ci:beso" \
  -H "Content-Type: application/json" \
  -d '{"permissions":[]}'
```

Do not specify a `secret` -- let Reposilite generate a strong random one.
The plugin never authenticates with the template token itself (it only reads
its name and routes), so the secret can remain unknown. See
[Template token secrets](#template-token-secrets) for why this matters.

## Installation

1. Download the plugin JAR from
   [GitHub Releases](https://github.com/BestSolution-at/reposilite-gitlab-oidc-auth/releases)
2. Copy the JAR to Reposilite's `plugins/` directory
3. Restart Reposilite
4. Configure via the web dashboard or `configuration.shared.json`
5. Create template tokens for your namespaces/projects

## Configuration

The plugin registers as a SharedSettings domain. Configuration appears under
the `gitlab_ci_auth` key in `configuration.shared.json`:

```json
{
  "gitlab_ci_auth": {
    "enabled": true,
    "gitlabUrl": "https://gitlab.example.com",
    "audience": "https://maven.example.com",
    "ciUsername": "gitlab-oidc",
    "jwksCacheTtl": 86400
  }
}
```

### Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `enabled` | yes | `false` | Enable the plugin |
| `gitlabUrl` | yes | -- | GitLab instance URL (e.g. `https://gitlab.example.com`) |
| `audience` | yes | -- | Expected `aud` claim in the JWT (must match `aud` in GitLab `id_tokens`) |
| `ciUsername` | no | `gitlab-oidc` | Username that triggers OIDC authentication |
| `jwksCacheTtl` | no | `86400` | How long to cache the JWKS keys (seconds) |

Authorization is configured entirely via template tokens in the database, not
in this configuration file.

## Authentication Chain

The plugin registers with priority `2.0`, which places it above
BasicAuthenticator (`0.0`) and LdapAuthenticator (`-1.0`) in the
authentication chain. This means:

1. **OIDC plugin** (priority 2.0) -- checks if username matches `ciUsername`
2. **BasicAuthenticator** (priority 0.0) -- standard token-based auth
3. **LdapAuthenticator** (priority -1.0) -- LDAP auth (if configured)

If the username does not match `ciUsername`, the plugin returns a failure and
the next authenticator in the chain handles the request. Existing admin tokens,
deploy tokens, and LDAP users are unaffected.

## Security Considerations

- **Branch/tag protection matters**: Only branches and tags marked as "protected"
  in GitLab produce `ref_protected: "true"` in the JWT. The plugin uses this to
  gate access to `gitlab-ci-protected:*` template token routes.

- **No long-lived credentials**: OIDC tokens are short-lived JWTs (typically
  5 minutes). They cannot be reused after expiry and do not need to be rotated
  or revoked manually.

- **Cryptographic verification only**: The plugin verifies JWT signatures
  against the GitLab JWKS endpoint. It does not make API calls to GitLab and
  does not require network access beyond the JWKS endpoint.

- **JWKS caching**: Public keys are cached in memory. The cache is refreshed
  when an unknown `kid` is encountered (key rotation) or after the configured
  TTL expires.

- **TEMPORARY tokens**: Created tokens use the `TEMPORARY` type and are scoped
  to the minimum required routes. Each job gets a unique token name
  (`gitlab-ci-{job_id}`).

- **Namespace isolation**: A CI job in namespace `beso` cannot access routes
  from template tokens in namespace `onacta`. The plugin derives the lookup
  names strictly from JWT claims.

- **Template token secrets**: Template tokens are regular Reposilite access
  tokens. If a template token has a weak or known secret (e.g. `"unused"`),
  an attacker could authenticate directly via BasicAuthenticator using that
  secret — bypassing the OIDC plugin entirely. Always let Reposilite generate
  a strong random secret when creating template tokens (do not specify a
  `secret` field). Since the OIDC plugin never uses the secret, it can remain
  unknown.

## GitLab CI Usage

### Maven

```yaml
deploy:
  image: maven:3.9-eclipse-temurin-21
  id_tokens:
    REPOSILITE_TOKEN:
      aud: https://maven.example.com
  script:
    - >
      mvn deploy
      -s ci-settings.xml
      -Dreposilite.username=gitlab-oidc
      -Dreposilite.password=${REPOSILITE_TOKEN}
```

With a `ci-settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>reposilite</id>
      <username>${reposilite.username}</username>
      <password>${reposilite.password}</password>
    </server>
  </servers>
</settings>
```

### Gradle

```yaml
deploy:
  image: gradle:8-jdk21
  id_tokens:
    REPOSILITE_TOKEN:
      aud: https://maven.example.com
  script:
    - >
      gradle publish
      -Preposilite.username=gitlab-oidc
      -Preposilite.password=${REPOSILITE_TOKEN}
```

> **Note**: The `id_tokens` keyword requires GitLab 15.7 or later.

## Compatibility

| Component | Version |
|-----------|---------|
| Reposilite | 3.5.x |
| Java | 11+ |
| Kotlin | 2.2+ (language level) |
| GitLab | 15.7+ (for `id_tokens`) |

## Development

```bash
# Build and run tests
./gradlew build

# Build the plugin JAR (shadow JAR with bundled dependencies)
./gradlew shadowJar

# The JAR is produced at:
# build/libs/reposilite-gitlab-oidc-auth-<version>.jar
```

### Project Structure

```text
src/
  main/kotlin/.../gitlab/
    GitlabCiAuthPlugin.kt        # Plugin entry point (ServiceLoader)
    GitlabCiAuthenticator.kt     # Core authentication logic
    GitlabCiAuthSettings.kt      # SharedSettings configuration
    AccessTokenOps.kt            # Testability abstraction
  test/kotlin/.../gitlab/
    GitlabCiAuthenticatorTest.kt # Unit tests (18 test cases)
    GitlabCiAuthenticatorTestFactory.kt
    FakeAccessTokenFacade.kt
    NoopJournalist.kt
```

## License

GPL-3.0-only
