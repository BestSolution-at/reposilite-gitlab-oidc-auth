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
 * plausible response. Implements the testable interface rather than extending
 * the final AccessTokenFacade.
 */
class FakeAccessTokenFacade : AccessTokenOps {

    var lastCreatedRequest: CreateAccessTokenRequest? = null
        private set

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
}
