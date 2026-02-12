package at.bestsolution.reposilite.auth.gitlab

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.reposilite.auth.Authenticator
import com.reposilite.auth.api.Credentials
import com.reposilite.journalist.Journalist
import com.reposilite.shared.ErrorResponse
import com.reposilite.token.AccessTokenType
import com.reposilite.token.RoutePermission
import com.reposilite.token.api.AccessTokenDto
import com.reposilite.token.api.CreateAccessTokenRequest
import io.javalin.http.HttpStatus
import panda.std.Result
import panda.std.reactive.Reference
import java.net.URI

class GitlabCiAuthenticator(
    private val journalist: Journalist,
    private val settings: Reference<GitlabCiAuthSettings>,
    private val accessTokenOps: AccessTokenOps,
    jwtProcessorOverride: DefaultJWTProcessor<SecurityContext>? = null,
) : Authenticator {

    private val jwtProcessor by lazy { jwtProcessorOverride ?: createJwtProcessor() }

    override fun authenticate(credentials: Credentials): Result<AccessTokenDto, ErrorResponse> {
        val config = settings.get()

        if (credentials.name != config.ciUsername) {
            return Result.error(ErrorResponse(HttpStatus.UNAUTHORIZED, "Invalid credentials"))
        }

        return try {
            val claims = jwtProcessor.process(credentials.secret, null)

            // Validate issuer (nimbus validates aud and exp, but not iss)
            if (claims.issuer != config.gitlabUrl) {
                journalist.logger.warn(
                    "gitlab-ci-auth: JWT issuer mismatch: expected=${config.gitlabUrl}, got=${claims.issuer}"
                )
                return Result.error(ErrorResponse(HttpStatus.UNAUTHORIZED, "Invalid token issuer"))
            }

            val jobId = claims.getStringClaim("job_id") ?: "unknown"
            val projectPath = claims.getStringClaim("project_path") ?: "unknown"
            val ref = claims.getStringClaim("ref") ?: "unknown"
            val refProtected = claims.getStringClaim("ref_protected")?.toBoolean() ?: false

            val tokenName = "gitlab-ci-$jobId"
            val routes = buildRoutes(config, refProtected)

            val response = accessTokenOps.createAccessToken(
                CreateAccessTokenRequest(
                    type = AccessTokenType.TEMPORARY,
                    name = tokenName,
                    secret = credentials.secret,
                    routes = routes,
                )
            )

            journalist.logger.debug(
                "gitlab-ci-auth: Authenticated job=$jobId project=$projectPath ref=$ref " +
                    "ref_protected=$refProtected routes=${formatRoutes(routes)}"
            )

            Result.ok(response.accessToken)
        } catch (e: Exception) {
            journalist.logger.warn("gitlab-ci-auth: JWT verification failed: ${e.message}")
            Result.error(ErrorResponse(HttpStatus.UNAUTHORIZED, "JWT verification failed"))
        }
    }

    override fun enabled(): Boolean = settings.get().enabled

    override fun priority(): Double = 2.0

    override fun realm(): String = "gitlab-ci-oidc"

    private fun buildRoutes(
        config: GitlabCiAuthSettings,
        refProtected: Boolean,
    ): Set<CreateAccessTokenRequest.Route> {
        val routes = mutableSetOf<CreateAccessTokenRequest.Route>()

        // READ routes for all CI builds
        for (repo in config.ciReadRepositories) {
            routes.add(
                CreateAccessTokenRequest.Route(
                    path = "/$repo",
                    permissions = setOf(RoutePermission.READ),
                )
            )
        }

        // WRITE routes only for protected branches
        if (refProtected) {
            for (repo in config.ciWriteRepositories) {
                routes.add(
                    CreateAccessTokenRequest.Route(
                        path = "/$repo",
                        permissions = setOf(RoutePermission.WRITE),
                    )
                )
            }
        }

        return routes
    }

    private fun createJwtProcessor(): DefaultJWTProcessor<SecurityContext> {
        val config = settings.get()
        val jwksUrl = URI("${config.gitlabUrl}/oauth/discovery/keys").toURL()
        val cacheTtlMs = config.jwksCacheTtl * 1000
        val cacheRefreshMs = cacheTtlMs

        val jwkSource = JWKSourceBuilder.create<SecurityContext>(jwksUrl)
            .cache(cacheTtlMs, cacheRefreshMs)
            .retrying(true)
            .build()

        val keySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)

        val processor = DefaultJWTProcessor<SecurityContext>()
        processor.jwsKeySelector = keySelector
        processor.jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(
            JWTClaimsSet.Builder()
                .audience(config.audience)
                .build(),
            setOf("sub", "iss", "exp", "aud"),
        )

        return processor
    }

    private fun formatRoutes(routes: Set<CreateAccessTokenRequest.Route>): String =
        routes.joinToString(", ") { route ->
            "/${route.path.trimStart('/')}:${route.permissions.joinToString("") { it.shortcut }}"
        }
}
