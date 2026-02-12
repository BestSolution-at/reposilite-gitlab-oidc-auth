package at.bestsolution.reposilite.auth.gitlab

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.reposilite.auth.api.Credentials
import com.reposilite.token.AccessTokenType
import com.reposilite.token.RoutePermission
import io.javalin.http.HttpStatus
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.Date

class GitlabCiAuthenticatorTest {

    private lateinit var rsaKey: RSAKey
    private lateinit var settings: GitlabCiAuthSettings
    private lateinit var fakeAccessTokenFacade: FakeAccessTokenFacade
    private lateinit var authenticator: GitlabCiAuthenticator

    companion object {
        private const val GITLAB_URL = "https://gitlab.example.com"
        private const val AUDIENCE = "https://maven.example.com"
        private const val CI_USERNAME = "gitlab-oidc"
    }

    @BeforeEach
    fun setUp() {
        rsaKey = RSAKeyGenerator(2048).keyID("test-key-1").generate()

        settings = GitlabCiAuthSettings(
            enabled = true,
            gitlabUrl = GITLAB_URL,
            audience = AUDIENCE,
            ciUsername = CI_USERNAME,
            ciReadRepositories = listOf("releases", "snapshots"),
            ciWriteRepositories = listOf("releases", "snapshots"),
        )

        fakeAccessTokenFacade = FakeAccessTokenFacade()
    }

    // --- Helper methods ---

    private fun createAuthenticator(
        jwksJson: String = """{"keys":[${rsaKey.toPublicJWK().toJSONString()}]}""",
    ): GitlabCiAuthenticator {
        val authenticator = GitlabCiAuthenticatorTestFactory.create(
            settings = settings,
            accessTokenOps = fakeAccessTokenFacade,
            jwksJson = jwksJson,
        )
        this.authenticator = authenticator
        return authenticator
    }

    private fun buildJwt(
        issuer: String = GITLAB_URL,
        audience: String = AUDIENCE,
        expiresAt: Date = Date.from(Instant.now().plusSeconds(300)),
        jobId: String = "12345",
        projectPath: String = "mygroup/myproject",
        ref: String = "main",
        refProtected: String = "true",
        signingKey: RSAKey = rsaKey,
    ): String {
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .subject("project_path:$projectPath:ref_type:branch:ref:$ref")
            .expirationTime(expiresAt)
            .claim("job_id", jobId)
            .claim("project_path", projectPath)
            .claim("ref", ref)
            .claim("ref_protected", refProtected)
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(signingKey.keyID)
            .build()

        val signedJwt = SignedJWT(header, claims)
        signedJwt.sign(RSASSASigner(signingKey))
        return signedJwt.serialize()
    }

    // --- TP-1.1: Valid JWT with ref_protected: true ---

    @Test
    fun `valid JWT with ref_protected true creates token with READ and WRITE routes`() {
        val auth = createAuthenticator()
        val jwt = buildJwt(refProtected = "true")

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isOk, "Authentication should succeed")
        val created = fakeAccessTokenFacade.lastCreatedRequest!!
        assertEquals(AccessTokenType.TEMPORARY, created.type)
        assertEquals("gitlab-ci-12345", created.name)

        val routePaths = created.routes.map { "${it.path}:${it.permissions}" }
        assertTrue(created.routes.any { it.path == "/releases" && RoutePermission.READ in it.permissions })
        assertTrue(created.routes.any { it.path == "/snapshots" && RoutePermission.READ in it.permissions })
        assertTrue(created.routes.any { it.path == "/releases" && RoutePermission.WRITE in it.permissions })
        assertTrue(created.routes.any { it.path == "/snapshots" && RoutePermission.WRITE in it.permissions })
    }

    // --- TP-1.2: Valid JWT with ref_protected: false ---

    @Test
    fun `valid JWT with ref_protected false creates token with READ-only routes`() {
        val auth = createAuthenticator()
        val jwt = buildJwt(refProtected = "false")

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isOk, "Authentication should succeed")
        val created = fakeAccessTokenFacade.lastCreatedRequest!!
        assertEquals(AccessTokenType.TEMPORARY, created.type)

        assertTrue(created.routes.any { it.path == "/releases" && RoutePermission.READ in it.permissions })
        assertTrue(created.routes.any { it.path == "/snapshots" && RoutePermission.READ in it.permissions })
        assertTrue(created.routes.none { RoutePermission.WRITE in it.permissions },
            "No WRITE routes for non-protected refs")
    }

    // --- TP-1.3: Expired JWT ---

    @Test
    fun `expired JWT is rejected`() {
        val auth = createAuthenticator()
        val jwt = buildJwt(expiresAt = Date.from(Instant.now().minusSeconds(60)))

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isErr, "Expired JWT should be rejected")
        assertEquals(HttpStatus.UNAUTHORIZED.code, result.error.status)
    }

    // --- TP-1.4: Wrong audience ---

    @Test
    fun `JWT with wrong audience is rejected`() {
        val auth = createAuthenticator()
        val jwt = buildJwt(audience = "https://wrong.example.com")

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isErr, "Wrong audience should be rejected")
    }

    // --- TP-1.5: Wrong issuer ---

    @Test
    fun `JWT with wrong issuer is rejected`() {
        val auth = createAuthenticator()
        val jwt = buildJwt(issuer = "https://evil-gitlab.example.com")

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isErr, "Wrong issuer should be rejected")
    }

    // --- TP-1.6: Unknown signing key ---

    @Test
    fun `JWT signed with unknown key is rejected`() {
        val auth = createAuthenticator()
        val unknownKey = RSAKeyGenerator(2048).keyID("unknown-key").generate()
        val jwt = buildJwt(signingKey = unknownKey)

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isErr, "Unknown signing key should be rejected")
    }

    // --- TP-1.7: Malformed JWT ---

    @Test
    fun `malformed JWT is rejected without crash`() {
        val auth = createAuthenticator()

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, "not-a-jwt"))

        assertTrue(result.isErr, "Malformed JWT should be rejected")
        assertEquals(HttpStatus.UNAUTHORIZED.code, result.error.status)
    }

    // --- TP-1.8: Non-CI username ---

    @Test
    fun `non-CI username returns failure for pass-through`() {
        val auth = createAuthenticator()

        val result = auth.authenticate(Credentials("127.0.0.1", "admin", "some-token"))

        assertTrue(result.isErr, "Non-CI username should return failure")
    }

    // --- TP-1.9: Concurrent jobs with different ref_protected ---

    @Test
    fun `concurrent jobs get separate tokens with correct routes`() {
        val auth = createAuthenticator()

        val jwtProtected = buildJwt(jobId = "100", refProtected = "true")
        val jwtUnprotected = buildJwt(jobId = "200", refProtected = "false")

        val result1 = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwtProtected))
        val request1 = fakeAccessTokenFacade.lastCreatedRequest!!

        val result2 = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwtUnprotected))
        val request2 = fakeAccessTokenFacade.lastCreatedRequest!!

        assertTrue(result1.isOk)
        assertTrue(result2.isOk)
        assertEquals("gitlab-ci-100", request1.name)
        assertEquals("gitlab-ci-200", request2.name)

        // Protected job has WRITE routes
        assertTrue(request1.routes.any { RoutePermission.WRITE in it.permissions })
        // Unprotected job has no WRITE routes
        assertTrue(request2.routes.none { RoutePermission.WRITE in it.permissions })
    }

    // --- TP-1.10: Token type is TEMPORARY ---

    @Test
    fun `created token is TEMPORARY type`() {
        val auth = createAuthenticator()
        val jwt = buildJwt()

        auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertEquals(AccessTokenType.TEMPORARY, fakeAccessTokenFacade.lastCreatedRequest!!.type)
    }

    // --- Additional: No MANAGER permission ---

    @Test
    fun `created token has no MANAGER permission`() {
        val auth = createAuthenticator()
        val jwt = buildJwt()

        auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        val created = fakeAccessTokenFacade.lastCreatedRequest!!
        assertTrue(created.permissions.isEmpty(), "Token should have no special permissions (no MANAGER)")
    }
}
