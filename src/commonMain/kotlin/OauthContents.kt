package net.lsafer.oauth

import io.ktor.http.*
import io.ktor.http.auth.*
import io.ktor.http.content.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import net.lsafer.oidc.oauth.OAuth

/**
 * Add an Oauth Challenge indicating an oauth `insufficient_scope` error.
 */
fun ApplicationCall.challengeInsufficientScope(
    realm: String,
    scope: String? = null,
    description: String? = null,
) {
    authentication.challenge(OauthChallengeKey, AuthenticationFailedCause.InvalidCredentials) { challenge, call ->
        call.respondInsufficientScope(realm, scope, description)
        challenge.complete()
    }
}

/**
 * Add an Oauth Challenge indicating an oauth `invalid_token` error.
 */
fun ApplicationCall.challengeInvalidToken(
    realm: String,
    description: String? = null,
) {
    authentication.challenge(OauthChallengeKey, AuthenticationFailedCause.InvalidCredentials) { challenge, call ->
        call.respondInvalidToken(realm, description)
        challenge.complete()
    }
}

/**
 * Add an Oauth Challenge indicating an oauth `invalid_request` error.
 */
fun ApplicationCall.challengeInvalidRequest(
    realm: String,
    description: String? = null,
) {
    authentication.challenge(OauthChallengeKey, AuthenticationFailedCause.InvalidCredentials) { challenge, call ->
        call.respondInvalidRequest(realm, description)
        challenge.complete()
    }
}

/**
 * Respond an Oauth Challenge indicating an oauth `insufficient_scope` error.
 */
suspend fun ApplicationCall.respondInsufficientScope(
    realm: String,
    scope: String? = null,
    description: String? = null,
) {
    respond(OauthInsufficientScopeContent(realm, scope, description))
}

/**
 * Respond an Oauth Challenge indicating an oauth `invalid_token` error.
 */
suspend fun ApplicationCall.respondInvalidToken(
    realm: String,
    description: String? = null,
) {
    respond(OauthInvalidTokenContent(realm, description))
}

/**
 * Respond an Oauth Challenge indicating an oauth `invalid_request` error.
 */
suspend fun ApplicationCall.respondInvalidRequest(
    realm: String,
    description: String? = null,
) {
    respond(OauthInvalidRequestContent(realm, description))
}

/**
 * An oauth empty response challenge with `insufficient_scope` error.
 */
class OauthInsufficientScopeContent(
    realm: String,
    scope: String? = null,
    description: String? = null,
) : OutgoingContent.NoContent() {
    override val status = HttpStatusCode.Forbidden
    override val headers = headers {
        val challenge = HttpAuthHeader.Parameterized(
            authScheme = AuthScheme.Bearer,
            parameters = buildMap {
                put(HttpAuthHeader.Parameters.Realm, realm)
                put(OAuth.Param.ERROR, OAuth.Error.INSUFFICIENT_SCOPE)
                if (description != null)
                    put(OAuth.Param.ERROR_DESCRIPTION, description)
                if (scope != null)
                    put(OAuth.Param.SCOPE, scope)
            }
        )

        set(HttpHeaders.WWWAuthenticate, challenge.render())
    }
}

/**
 * An oauth empty response challenge with `invalid_token` error.
 */
class OauthInvalidTokenContent(
    realm: String,
    description: String? = null,
) : OutgoingContent.NoContent() {
    override val status = HttpStatusCode.Unauthorized
    override val headers = headers {
        val challenge = HttpAuthHeader.Parameterized(
            authScheme = AuthScheme.Bearer,
            parameters = buildMap {
                put(HttpAuthHeader.Parameters.Realm, realm)
                put(OAuth.Param.ERROR, OAuth.Error.INVALID_TOKEN)
                if (description != null)
                    put(OAuth.Param.ERROR_DESCRIPTION, description)
            }
        )

        set(HttpHeaders.WWWAuthenticate, challenge.render())
    }
}

/**
 * An oauth empty response challenge with `invalid_request` error.
 */
class OauthInvalidRequestContent(
    realm: String,
    description: String? = null,
) : OutgoingContent.NoContent() {
    override val status = HttpStatusCode.BadRequest
    override val headers = headers {
        val challenge = HttpAuthHeader.Parameterized(
            authScheme = AuthScheme.Bearer,
            parameters = buildMap {
                put(HttpAuthHeader.Parameters.Realm, realm)
                put(OAuth.Param.ERROR, OAuth.Error.INVALID_REQUEST)
                if (description != null)
                    put(OAuth.Param.ERROR_DESCRIPTION, description)
            }
        )

        set(HttpHeaders.WWWAuthenticate, challenge.render())
    }
}
