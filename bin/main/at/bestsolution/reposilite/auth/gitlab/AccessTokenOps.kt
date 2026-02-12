package at.bestsolution.reposilite.auth.gitlab

import com.reposilite.token.AccessTokenFacade
import com.reposilite.token.AccessTokenIdentifier
import com.reposilite.token.Route
import com.reposilite.token.api.AccessTokenDto
import com.reposilite.token.api.CreateAccessTokenRequest
import com.reposilite.token.api.CreateAccessTokenResponse

/**
 * Abstraction over AccessTokenFacade for testability.
 * In production, delegates to the real facade. In tests, uses a fake.
 */
interface AccessTokenOps {
    fun createAccessToken(request: CreateAccessTokenRequest): CreateAccessTokenResponse
    fun getAccessToken(name: String): AccessTokenDto?
    fun getRoutes(identifier: AccessTokenIdentifier): Set<Route>
}

/** Wraps a real AccessTokenFacade into the testable interface. */
fun AccessTokenFacade.asOps(): AccessTokenOps = object : AccessTokenOps {
    override fun createAccessToken(request: CreateAccessTokenRequest): CreateAccessTokenResponse =
        this@asOps.createAccessToken(request)

    override fun getAccessToken(name: String): AccessTokenDto? =
        this@asOps.getAccessToken(name)

    override fun getRoutes(identifier: AccessTokenIdentifier): Set<Route> =
        this@asOps.getRoutes(identifier)
}
