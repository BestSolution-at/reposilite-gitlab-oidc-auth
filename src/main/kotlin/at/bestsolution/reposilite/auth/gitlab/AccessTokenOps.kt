package at.bestsolution.reposilite.auth.gitlab

import com.reposilite.token.AccessTokenFacade
import com.reposilite.token.api.CreateAccessTokenRequest
import com.reposilite.token.api.CreateAccessTokenResponse

/**
 * Abstraction over AccessTokenFacade for testability.
 * In production, delegates to the real facade. In tests, uses a fake.
 */
fun interface AccessTokenOps {
    fun createAccessToken(request: CreateAccessTokenRequest): CreateAccessTokenResponse
}

/** Wraps a real AccessTokenFacade into the testable interface. */
fun AccessTokenFacade.asOps(): AccessTokenOps = AccessTokenOps { request ->
    this.createAccessToken(request)
}
