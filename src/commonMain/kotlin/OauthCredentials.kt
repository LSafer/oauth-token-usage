package net.lsafer.oauth

import io.ktor.http.*
import io.ktor.http.auth.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import kotlinx.serialization.Serializable
import net.lsafer.oidc.oauth.OAuth

@Serializable
abstract class OauthCredentials {
    abstract val token: String

    @Serializable
    data class AuthorizationHeader(override val token: String) :
        OauthCredentials()

    @Serializable
    data class FormEncodedBody(override val token: String) :
        OauthCredentials()

    @Serializable
    data class UriQuery(override val token: String) :
        OauthCredentials()
}

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
