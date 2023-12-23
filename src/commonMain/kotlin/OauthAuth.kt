package net.lsafer.oauth

import io.ktor.server.application.*
import io.ktor.server.auth.*

fun AuthenticationConfig.oauth(
    name: String? = null,
    block: OauthAuthenticationProvider.Config.() -> Unit,
) {
    val config = OauthAuthenticationProvider.Config(name)
    config.apply(block)
    val provider = OauthAuthenticationProvider(config)
    register(provider)
}

class OauthAuthenticationProvider(config: Config) : AuthenticationProvider(config) {
    private val authenticate: AuthenticationFunction<OauthCredentials> = config.authenticate
    private val realm = config.realm

    override suspend fun onAuthenticate(context: AuthenticationContext) {
        val credentials = context.call.receiveOauthCredentialsSet()

        if (credentials.isEmpty()) {
            context.challenge(challengeKey, AuthenticationFailedCause.NoCredentials) { challenge, call ->
                call.respondInvalidToken(realm)
                challenge.complete()
            }
            return
        }

        if (credentials.size != 1) {
            context.challenge(challengeKey, AuthenticationFailedCause.InvalidCredentials) { challenge, call ->
                call.respondInvalidRequest(realm)
                challenge.complete()
            }
            return
        }

        val principal = authenticate(context.call, credentials.single())

        if (principal == null) {
            context.challenge(challengeKey, AuthenticationFailedCause.InvalidCredentials) { challenge, call ->
                call.respondInvalidToken(realm)
                challenge.complete()
            }
            return
        }

        context.principal(principal)
    }

    class Config internal constructor(name: String?) : AuthenticationProvider.Config(name) {
        var realm: String = "Ktor Server"

        internal var authenticate: AuthenticationFunction<OauthCredentials> = {
            throw NotImplementedError(
                "Oauth auth authenticate function is not specified"
            )
        }

        fun authenticate(block: suspend ApplicationCall.(OauthCredentials) -> Principal?) {
            authenticate = block
        }
    }
}

private val challengeKey: Any = "OauthAuth"
