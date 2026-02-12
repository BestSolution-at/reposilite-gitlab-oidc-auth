package at.bestsolution.reposilite.auth.gitlab

import com.reposilite.token.AccessTokenIdentifier
import com.reposilite.token.AccessTokenType
import com.reposilite.token.Route
import com.reposilite.token.api.AccessTokenDto
import com.reposilite.token.api.CreateAccessTokenRequest
import com.reposilite.token.api.CreateAccessTokenResponse
import java.time.LocalDate

/**
 * Minimal fake that records the last createAccessToken call and returns a
 * plausible response. Also supports registering template tokens for lookup
 * during template token authorization tests.
 */
class FakeAccessTokenFacade : AccessTokenOps {

    var lastCreatedRequest: CreateAccessTokenRequest? = null
        private set

    /** Template tokens registered for lookup by name. */
    private val templateTokens = mutableMapOf<String, AccessTokenDto>()
    private val templateRoutes = mutableMapOf<AccessTokenIdentifier, Set<Route>>()
    private var nextId = 1L

    /** Register a template token with the given name and routes. */
    fun addTemplateToken(name: String, routes: Set<Route>) {
        val identifier = AccessTokenIdentifier(type = AccessTokenType.PERSISTENT, value = nextId++.toInt())
        val dto = AccessTokenDto(
            identifier = identifier,
            name = name,
            createdAt = LocalDate.now(),
            description = "",
        )
        templateTokens[name] = dto
        templateRoutes[identifier] = routes
    }

    override fun createAccessToken(request: CreateAccessTokenRequest): CreateAccessTokenResponse {
        lastCreatedRequest = request

        val identifier = AccessTokenIdentifier(type = request.type)
        val dto = AccessTokenDto(
            identifier = identifier,
            name = request.name,
            createdAt = LocalDate.now(),
            description = "",
        )

        val routes = request.routes.flatMapTo(mutableSetOf()) { route ->
            route.permissions.map { permission ->
                Route(path = route.path, permission = permission)
            }
        }

        return CreateAccessTokenResponse(
            accessToken = dto,
            permissions = emptySet(),
            routes = routes,
            secret = request.secret ?: "generated-secret",
        )
    }

    override fun getAccessToken(name: String): AccessTokenDto? =
        templateTokens[name]

    override fun getRoutes(identifier: AccessTokenIdentifier): Set<Route> =
        templateRoutes[identifier] ?: emptySet()
}
