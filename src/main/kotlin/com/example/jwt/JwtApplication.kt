package com.example.jwt

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.support.beans
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.web.servlet.function.ServerResponse
import org.springframework.web.servlet.function.router
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.*


@SpringBootApplication
class JwtApplication

fun main(args: Array<String>) {
    runApplication<JwtApplication>(*args){
        addInitializers(beans {
            bean {
                router {
                    GET("/secured/test"){ ServerResponse.ok().body("test ok") }
                }
            }

            bean {
                val http: HttpSecurity = ref()
                OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)

                val configurer: OAuth2AuthorizationServerConfigurer<HttpSecurity> =
                    OAuth2AuthorizationServerConfigurer()

                configurer
                    .clientAuthentication {
                        it.authenticationProvider(object : AuthenticationProvider{
                            override fun authenticate(authentication: Authentication): Authentication {
                                return authentication
                            }

                            override fun supports(authentication: Class<*>): Boolean {
                                return true
                            }
                        });
                    }

                http.build()
            }

            bean {
                val http: HttpSecurity = ref()
                http.authorizeHttpRequests { authz ->
                    authz.antMatchers("/secured/*")
                        .hasAuthority("SCOPE_efc")
                        .and()
                        .oauth2ResourceServer()
                        .jwt()
                }
                http.build()
            }

            bean {
                ProviderSettings
                    .builder()
                    .issuer("http://auth-server:8080")
                    .build();
            }

            bean { BCryptPasswordEncoder() }

            bean {
                val encoder: PasswordEncoder = ref()

                val tokenSettings = TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(5))
                    .build()
                val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("messaging-client")
                    .clientSecret(encoder.encode("secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://auth-server:8080/athorization_code")
                    .scope("efc")
                    .tokenSettings(tokenSettings)
                    .build()

                InMemoryRegisteredClientRepository(registeredClient)
            }

            bean {
                val rsaKey: RSAKey = JwKUtils.generateRsa()
                val jwkSet = JWKSet(rsaKey)
                JWKSource { jwkSelector: JWKSelector, _: SecurityContext? ->
                    jwkSelector.select(jwkSet)
                }
            }

            bean {
                val encoder: PasswordEncoder = ref()

                val user = User.builder()
                    .passwordEncoder(encoder::encode)
                    .username("user1")
                    .password("password")
                    .roles("USER")
                    .build()
                InMemoryUserDetailsManager(user)
            }
        })
    }
}

//@Configuration(proxyBeanMethods = false)
class MyConfiguration{

    @Bean
    fun jwtCustomizer(userDetailsService: UserDetailsService, passwordEncoder: PasswordEncoder) =
        OAuth2TokenCustomizer<JwtEncodingContext>{ context ->
            if (OAuth2TokenType.ACCESS_TOKEN == context.tokenType) {
                context.headers.type("JWT").build()

                val username = context
                    .getAuthorizationGrant<OAuth2ClientCredentialsAuthenticationToken>()
                    .additionalParameters["username"]
                val password = context
                    .getAuthorizationGrant<OAuth2ClientCredentialsAuthenticationToken>()
                    .additionalParameters["password"]

                val user = userDetailsService.loadUserByUsername(username as String)
                val encodedPassword = passwordEncoder.encode(password as String)

                if(encodedPassword != user.password){
                    throw AuthenticationCredentialsNotFoundException("cccc")
                }
            }
        }
}

object JwKUtils {
    private fun generateRsaKey(): KeyPair {
        val keyPair: KeyPair = try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPairGenerator.generateKeyPair()
        } catch (ex: Exception) {
            throw IllegalStateException(ex)
        }
        return keyPair
    }

    fun generateRsa(): RSAKey {
        val keyPair: KeyPair = generateRsaKey()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }

}