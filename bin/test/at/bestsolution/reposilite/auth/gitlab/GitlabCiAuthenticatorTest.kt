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
import com.reposilite.token.Route
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
        namespacePath: String = "mygroup",
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
            .claim("namespace_path", namespacePath)
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

    // =========================================================================
    // TP-1: JWT Verification Tests
    // =========================================================================

    // --- TP-1.1: Valid JWT creates token ---

    @Test
    fun `valid JWT creates TEMPORARY token`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.mygroup",
            setOf(Route("/releases", RoutePermission.READ)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt()

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isOk, "Authentication should succeed")
        assertEquals("gitlab-ci-12345", fakeAccessTokenFacade.lastCreatedRequest!!.name)
    }

    // --- TP-1.2: Expired JWT ---

    @Test
    fun `expired JWT is rejected`() {
        val auth = createAuthenticator()
        val jwt = buildJwt(expiresAt = Date.from(Instant.now().minusSeconds(60)))

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isErr, "Expired JWT should be rejected")
        assertEquals(HttpStatus.UNAUTHORIZED.code, result.error.status)
    }

    // --- TP-1.3: Wrong audience ---

    @Test
    fun `JWT with wrong audience is rejected`() {
        val auth = createAuthenticator()
        val jwt = buildJwt(audience = "https://wrong.example.com")

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isErr, "Wrong audience should be rejected")
    }

    // --- TP-1.3a: Trailing slash in JWT audience ---

    @Test
    fun `tolerates trailing slash in JWT audience`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.mygroup",
            setOf(Route("/releases", RoutePermission.READ)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt(audience = "$AUDIENCE/")

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isOk, "Trailing slash in JWT audience should be tolerated")
        assertEquals("gitlab-ci-12345", fakeAccessTokenFacade.lastCreatedRequest!!.name)
    }

    // --- TP-1.3b: Trailing slash in configured audience ---

    @Test
    fun `tolerates trailing slash in configured audience`() {
        settings = settings.copy(audience = "$AUDIENCE/")
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.mygroup",
            setOf(Route("/releases", RoutePermission.READ)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt()

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isOk, "Trailing slash in configured audience should be tolerated")
        assertEquals("gitlab-ci-12345", fakeAccessTokenFacade.lastCreatedRequest!!.name)
    }

    // --- TP-1.4: Wrong issuer ---

    @Test
    fun `JWT with wrong issuer is rejected`() {
        val auth = createAuthenticator()
        val jwt = buildJwt(issuer = "https://evil-gitlab.example.com")

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isErr, "Wrong issuer should be rejected")
    }

    // --- TP-1.5: Unknown signing key ---

    @Test
    fun `JWT signed with unknown key is rejected`() {
        val auth = createAuthenticator()
        val unknownKey = RSAKeyGenerator(2048).keyID("unknown-key").generate()
        val jwt = buildJwt(signingKey = unknownKey)

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isErr, "Unknown signing key should be rejected")
    }

    // --- TP-1.6: Malformed JWT ---

    @Test
    fun `malformed JWT is rejected without crash`() {
        val auth = createAuthenticator()

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, "not-a-jwt"))

        assertTrue(result.isErr, "Malformed JWT should be rejected")
        assertEquals(HttpStatus.UNAUTHORIZED.code, result.error.status)
    }

    // --- TP-1.7: Non-CI username ---

    @Test
    fun `non-CI username returns failure for pass-through`() {
        val auth = createAuthenticator()

        val result = auth.authenticate(Credentials("127.0.0.1", "admin", "some-token"))

        assertTrue(result.isErr, "Non-CI username should return failure")
    }

    // --- TP-1.8: Concurrent jobs ---

    @Test
    fun `concurrent jobs get separate tokens`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.mygroup",
            setOf(Route("/releases", RoutePermission.READ)),
        )
        val auth = createAuthenticator()

        val jwt1 = buildJwt(jobId = "100")
        val jwt2 = buildJwt(jobId = "200")

        val result1 = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt1))
        val request1 = fakeAccessTokenFacade.lastCreatedRequest!!

        val result2 = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt2))
        val request2 = fakeAccessTokenFacade.lastCreatedRequest!!

        assertTrue(result1.isOk)
        assertTrue(result2.isOk)
        assertEquals("gitlab-ci-100", request1.name)
        assertEquals("gitlab-ci-200", request2.name)
    }

    // --- TP-1.9: Token type is TEMPORARY ---

    @Test
    fun `created token is TEMPORARY type`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.mygroup",
            setOf(Route("/releases", RoutePermission.READ)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt()

        auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertEquals(AccessTokenType.TEMPORARY, fakeAccessTokenFacade.lastCreatedRequest!!.type)
    }

    // --- TP-1.10: No MANAGER permission ---

    @Test
    fun `created token has no MANAGER permission`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.mygroup",
            setOf(Route("/releases", RoutePermission.READ)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt()

        auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        val created = fakeAccessTokenFacade.lastCreatedRequest!!
        assertTrue(created.permissions.isEmpty(), "Token should have no special permissions (no MANAGER)")
    }

    // =========================================================================
    // TP-2: Template Token Lookup Tests
    // =========================================================================

    // --- TP-2.1: Unprotected ref → namespace token only ---

    @Test
    fun `unprotected ref gets routes from gitlab-ci namespace token only`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.beso",
            setOf(Route("/beso-releases", RoutePermission.READ)),
        )
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci-protected.beso",
            setOf(Route("/beso-releases", RoutePermission.WRITE)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt(
            namespacePath = "beso",
            projectPath = "beso/my-app",
            refProtected = "false",
        )

        auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        val routes = fakeAccessTokenFacade.lastCreatedRequest!!.routes
        assertTrue(routes.any { it.path == "/beso-releases" && RoutePermission.READ in it.permissions },
            "Should have READ from gitlab-ci.beso")
        assertTrue(routes.none { RoutePermission.WRITE in it.permissions },
            "Should NOT have WRITE (not protected)")
    }

    // --- TP-2.2: Protected ref → namespace + protected namespace tokens ---

    @Test
    fun `protected ref gets routes from both gitlab-ci and gitlab-ci-protected namespace tokens`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.beso",
            setOf(Route("/beso-releases", RoutePermission.READ)),
        )
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci-protected.beso",
            setOf(Route("/beso-releases", RoutePermission.WRITE)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt(
            namespacePath = "beso",
            projectPath = "beso/my-app",
            refProtected = "true",
        )

        auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        val routes = fakeAccessTokenFacade.lastCreatedRequest!!.routes
        assertTrue(routes.any { it.path == "/beso-releases" && RoutePermission.READ in it.permissions },
            "Should have READ from gitlab-ci.beso")
        assertTrue(routes.any { it.path == "/beso-releases" && RoutePermission.WRITE in it.permissions },
            "Should have WRITE from gitlab-ci-protected.beso")
    }

    // --- TP-2.3: Namespace + project token union ---

    @Test
    fun `project token routes are unioned with namespace token routes`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.beso",
            setOf(Route("/shared-releases", RoutePermission.READ)),
        )
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.beso/my-app",
            setOf(Route("/internal-releases", RoutePermission.READ)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt(
            namespacePath = "beso",
            projectPath = "beso/my-app",
            refProtected = "false",
        )

        auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        val routes = fakeAccessTokenFacade.lastCreatedRequest!!.routes
        assertTrue(routes.any { it.path == "/shared-releases" && RoutePermission.READ in it.permissions },
            "Should have READ from gitlab-ci.beso (namespace)")
        assertTrue(routes.any { it.path == "/internal-releases" && RoutePermission.READ in it.permissions },
            "Should have READ from gitlab-ci.beso/my-app (project)")
    }

    // --- TP-2.4: Protected ref → all four lookups ---

    @Test
    fun `protected ref looks up all four token combinations`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.beso",
            setOf(Route("/repo-a", RoutePermission.READ)),
        )
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.beso/my-app",
            setOf(Route("/repo-b", RoutePermission.READ)),
        )
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci-protected.beso",
            setOf(Route("/repo-c", RoutePermission.WRITE)),
        )
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci-protected.beso/my-app",
            setOf(Route("/repo-d", RoutePermission.WRITE)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt(
            namespacePath = "beso",
            projectPath = "beso/my-app",
            refProtected = "true",
        )

        auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        val routes = fakeAccessTokenFacade.lastCreatedRequest!!.routes
        assertTrue(routes.any { it.path == "/repo-a" }, "Should include routes from gitlab-ci.beso")
        assertTrue(routes.any { it.path == "/repo-b" }, "Should include routes from gitlab-ci.beso/my-app")
        assertTrue(routes.any { it.path == "/repo-c" }, "Should include routes from gitlab-ci-protected.beso")
        assertTrue(routes.any { it.path == "/repo-d" }, "Should include routes from gitlab-ci-protected.beso/my-app")
    }

    // --- TP-2.5: No matching templates → zero routes ---

    @Test
    fun `no matching template tokens results in zero routes`() {
        // No template tokens registered
        val auth = createAuthenticator()
        val jwt = buildJwt(
            namespacePath = "unknown-group",
            projectPath = "unknown-group/unknown-project",
        )

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isOk, "Authentication should still succeed (valid JWT)")
        val routes = fakeAccessTokenFacade.lastCreatedRequest!!.routes
        assertTrue(routes.isEmpty(), "Should have zero routes (no matching templates)")
    }

    // --- TP-2.6: Namespace isolation ---

    @Test
    fun `namespace isolation - beso project does not get onacta routes`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.beso",
            setOf(Route("/beso-releases", RoutePermission.READ)),
        )
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.onacta",
            setOf(Route("/onacta-releases", RoutePermission.READ)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt(
            namespacePath = "beso",
            projectPath = "beso/my-app",
            refProtected = "false",
        )

        auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        val routes = fakeAccessTokenFacade.lastCreatedRequest!!.routes
        assertTrue(routes.any { it.path == "/beso-releases" }, "Should have beso routes")
        assertTrue(routes.none { it.path == "/onacta-releases" }, "Should NOT have onacta routes")
    }

    // --- TP-2.7: Project isolation ---

    @Test
    fun `project isolation - other project does not get project-specific routes`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci-protected.beso/team-a-libs",
            setOf(Route("/internal-releases", RoutePermission.WRITE)),
        )
        val auth = createAuthenticator()
        val jwt = buildJwt(
            namespacePath = "beso",
            projectPath = "beso/other-project",
            refProtected = "true",
        )

        auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        val routes = fakeAccessTokenFacade.lastCreatedRequest!!.routes
        assertTrue(routes.none { it.path == "/internal-releases" },
            "beso/other-project should NOT get routes from gitlab-ci-protected.beso/team-a-libs")
    }

    // --- TP-2.8: Template token with no routes ---

    @Test
    fun `template token with no routes contributes nothing`() {
        fakeAccessTokenFacade.addTemplateToken(
            "gitlab-ci.beso",
            emptySet(), // no routes
        )
        val auth = createAuthenticator()
        val jwt = buildJwt(
            namespacePath = "beso",
            projectPath = "beso/my-app",
            refProtected = "false",
        )

        val result = auth.authenticate(Credentials("127.0.0.1", CI_USERNAME, jwt))

        assertTrue(result.isOk, "Authentication should succeed")
        val routes = fakeAccessTokenFacade.lastCreatedRequest!!.routes
        assertTrue(routes.isEmpty(), "Empty template token should contribute no routes")
    }
}
