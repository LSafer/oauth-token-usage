package net.lsafer.oauth

import io.ktor.http.*
import io.ktor.http.auth.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import kotlinx.serialization.Serializable
import net.lsafer.oidc.oauth.OAuth

/**
 * A valid Oauth Credentials according to Oauth Bearer Token Usage.
 */
@Serializable
abstract class OauthCredentials {
    /**
     * The bearer access token.
     */
    abstract val token: String

    /**
     * An access token passed with Authorization Header
     */
    @Serializable
    data class AuthorizationHeader(override val token: String) :
        OauthCredentials()

    /**
     * An access token passed within a Form Encoded Body.
     */
    @Serializable
    data class FormEncodedBody(override val token: String) :
        OauthCredentials()

    /**
     * An access token passed within the Uri Query.
     */
    @Serializable
    data class UriQuery(override val token: String) :
        OauthCredentials()
}

/**
 * Receive a set containing all the Access Tokens passed by the caller.
 */
suspend fun ApplicationCall.receiveOauthCredentialsSet(): Set<OauthCredentials> {
    // https://datatracker.ietf.org/doc/html/rfc6750#section-2

    fun decodeAuthorizationRequestHeaderField(): OauthCredentials? {
        val header = try {
            request.parseAuthorizationHeader()
        } catch (e: Throwable) {
            return null
        }

        if (header !is HttpAuthHeader.Single)
            return null

        if (!header.authScheme.equals(AuthScheme.Bearer, ignoreCase = true))
            return null

        return OauthCredentials.AuthorizationHeader(header.blob)
    }

    suspend fun decodeFormEncodedBodyParameter(): OauthCredentials? {
        if (request.httpMethod != HttpMethod.Post)
            return null

        val parameters = try {
            receiveParameters()
        } catch (_: Throwable) {
            return null
        }

        val token = parameters[OAuth.Param.ACCESS_TOKEN]

        token ?: return null

        return OauthCredentials.FormEncodedBody(token)
    }

    fun decodeUriQueryParameter(): OauthCredentials? {
        val token = request.queryParameters[OAuth.Param.ACCESS_TOKEN]

        token ?: return null

        return OauthCredentials.UriQuery(token)
    }

    return setOfNotNull(
        decodeAuthorizationRequestHeaderField(),
        decodeFormEncodedBodyParameter(),
        decodeUriQueryParameter(),
    )
}
