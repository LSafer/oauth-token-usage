package net.lsafer.oauth

import io.ktor.http.*
import io.ktor.http.auth.*
import io.ktor.http.content.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import net.lsafer.oidc.oauth.OAuth

suspend fun ApplicationCall.respondInsufficientScope(
    realm: String,
    scope: String? = null,
    description: String? = null,
) {
    respond(OauthInsufficientScopeContent(realm, scope, description))
}

suspend fun ApplicationCall.respondInvalidToken(
    realm: String,
    description: String? = null,
) {
    respond(OauthInvalidTokenContent(realm, description))
}

suspend fun ApplicationCall.respondInvalidRequest(
    realm: String,
    description: String? = null,
) {
    respond(OauthInvalidRequestContent(realm, description))
}

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
