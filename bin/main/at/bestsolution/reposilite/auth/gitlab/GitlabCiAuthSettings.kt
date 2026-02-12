package at.bestsolution.reposilite.auth.gitlab

import com.reposilite.configuration.shared.api.Doc
import com.reposilite.configuration.shared.api.SharedSettings
import io.javalin.openapi.JsonSchema

@JsonSchema(requireNonNulls = false)
@Doc(title = "Gitlab CI Auth", description = "GitLab CI OIDC authentication for CI/CD builds")
data class GitlabCiAuthSettings(
    @get:Doc(title = "Enabled", description = "Enable GitLab CI OIDC authentication")
    val enabled: Boolean = false,
    @get:Doc(title = "GitLab URL", description = "Base URL of the GitLab instance")
    val gitlabUrl: String = "",
    @get:Doc(title = "Audience", description = "Expected aud claim value (Reposilite FQDN)")
    val audience: String = "",
    @get:Doc(title = "CI Username", description = "Username that triggers OIDC verification")
    val ciUsername: String = "gitlab-oidc",
    @get:Doc(title = "JWKS Cache TTL", description = "Time in seconds to cache JWKS keys")
    val jwksCacheTtl: Long = 86400,
) : SharedSettings
