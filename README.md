# reposilite-gitlab-oidc-auth

A [Reposilite](https://reposilite.com/) 3.5.x plugin that authenticates GitLab CI
jobs using [OIDC ID tokens](https://docs.gitlab.com/ci/secrets/id_token_authentication/).

GitLab CI pipelines present a short-lived JWT as the password via HTTP Basic
Auth. The plugin verifies the token cryptographically against the GitLab JWKS
endpoint and creates a TEMPORARY access token with route-based permissions
derived from the JWT claims. This allows fine-grained repository access control
without long-lived credentials.

## How It Works

1. GitLab CI job requests an OIDC ID token (`id_tokens` keyword, GitLab 15.7+)
2. The job authenticates to Reposilite using HTTP Basic Auth:
   - **username**: `gitlab-oidc` (configurable)
   - **password**: the OIDC JWT
3. The plugin verifies the JWT signature via the GitLab JWKS endpoint
4. On success, the plugin creates a TEMPORARY access token with routes
   derived from the JWT claims and plugin configuration
5. Non-CI users (any other username) pass through to the next authenticator
   (BasicAuthenticator or LDAP)

## Route Permissions

The plugin assigns route-based permissions (READ/WRITE on repository paths)
based on the `ref_protected` JWT claim.

| Condition | Permissions |
|-----------|-------------|
| Every valid JWT | READ on all `ciReadRepositories` |
| JWT with `ref_protected: "true"` | READ + WRITE on `ciWriteRepositories` |
| JWT with `ref_protected: "false"` | READ only (no WRITE) |

### Example

With this configuration:

```json
{
  "ciReadRepositories": ["releases", "snapshots"],
  "ciWriteRepositories": ["releases", "snapshots"]
}
```

**Protected branch/tag build** (e.g. `main`):

- READ on `/releases`, `/snapshots`
- WRITE on `/releases`, `/snapshots`

**Feature branch build** (e.g. `feature/foo`):

- READ on `/releases`, `/snapshots`
- No WRITE access

## Installation

1. Build the plugin JAR (see [Development](#development))
2. Copy the JAR to Reposilite's `plugins/` directory
3. Restart Reposilite
4. Configure via the web dashboard or `configuration.shared.json`

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
    "jwksCacheTtl": 86400,
    "ciReadRepositories": ["releases", "snapshots"],
    "ciWriteRepositories": ["releases", "snapshots"]
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
| `ciReadRepositories` | yes | `[]` | Repository names for READ access (all CI builds) |
| `ciWriteRepositories` | yes | `[]` | Repository names for WRITE access (protected refs only) |

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
  in GitLab produce `ref_protected: "true"` in the JWT. Without this, CI builds
  only get READ access to repositories.

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
    GitlabCiAuthenticatorTest.kt # Unit tests (11 test cases)
    GitlabCiAuthenticatorTestFactory.kt
    FakeAccessTokenFacade.kt
    NoopJournalist.kt
```

## License

GPL-3.0-only
