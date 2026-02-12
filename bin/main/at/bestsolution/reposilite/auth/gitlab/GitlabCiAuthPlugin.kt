package at.bestsolution.reposilite.auth.gitlab

import com.reposilite.auth.AuthenticationFacade
import com.reposilite.configuration.shared.SharedConfigurationFacade
import com.reposilite.plugin.api.Facade
import com.reposilite.plugin.api.Plugin
import com.reposilite.plugin.api.ReposilitePlugin
import com.reposilite.plugin.facade
import com.reposilite.token.AccessTokenFacade

@Plugin(
    name = "gitlab-ci-auth",
    dependencies = ["access-token", "shared-configuration"],
    settings = GitlabCiAuthSettings::class,
)
class GitlabCiAuthPlugin : ReposilitePlugin() {

    override fun initialize(): Facade? {
        val sharedConfigFacade = facade<SharedConfigurationFacade>()
        val accessTokenFacade = facade<AccessTokenFacade>()
        val authFacade = facade<AuthenticationFacade>()

        val settings = sharedConfigFacade.getDomainSettings<GitlabCiAuthSettings>()
        val config = settings.get()

        if (!config.enabled) {
            logger.info("gitlab-ci-auth: Disabled")
            return null
        }

        require(config.gitlabUrl.isNotBlank()) { "gitlab-ci-auth: gitlabUrl is required" }
        require(config.audience.isNotBlank()) { "gitlab-ci-auth: audience is required" }

        logger.info("gitlab-ci-auth: Enabled for GitLab ${config.gitlabUrl}, audience=${config.audience}")

        authFacade.registerAuthenticator(
            GitlabCiAuthenticator(
                journalist = this,
                settings = settings,
                accessTokenOps = accessTokenFacade.asOps(),
            )
        )

        return null
    }
}
