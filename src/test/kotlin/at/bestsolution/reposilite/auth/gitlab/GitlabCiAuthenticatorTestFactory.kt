package at.bestsolution.reposilite.auth.gitlab

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import panda.std.reactive.Reference

/**
 * Creates GitlabCiAuthenticator instances for testing, using an in-memory
 * JWKS source instead of fetching from a real HTTP endpoint.
 */
object GitlabCiAuthenticatorTestFactory {

    fun create(
        settings: GitlabCiAuthSettings,
        accessTokenOps: AccessTokenOps,
        jwksJson: String,
    ): GitlabCiAuthenticator {
        val jwkSet = JWKSet.parse(jwksJson)
        val jwkSource = ImmutableJWKSet<SecurityContext>(jwkSet)
        val keySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)

        val processor = DefaultJWTProcessor<SecurityContext>()
        processor.jwsKeySelector = keySelector
        processor.jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(
            JWTClaimsSet.Builder()
                .audience(settings.audience)
                .build(),
            setOf("sub", "iss", "exp", "aud"),
        )

        val settingsRef = Reference.reference(settings)

        return GitlabCiAuthenticator(
            journalist = NoopJournalist,
            settings = settingsRef,
            accessTokenOps = accessTokenOps,
            jwtProcessorOverride = processor,
        )
    }
}
