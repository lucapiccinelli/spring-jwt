package com.example.jwt

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.support.beans
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.config.ClientSettings
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.web.servlet.function.ServerResponse
import org.springframework.web.servlet.function.router
import java.time.Duration
import java.util.*


@SpringBootApplication
class JwtApplicationFE

fun main(args: Array<String>) {
    val hostname = "127.0.0.1"
    val port = "8080"
    val rootUri = "http://$hostname:$port"

    runApplication<JwtApplicationFE>(*args){
        addInitializers(beans {
            bean {
                router {
                    GET("/secured/test") {
                        val name = it.principal()
                            .map { it.name }
                            .orElse("no one")

                        ServerResponse.ok().body("test ok $name")
                    }
                }
            }

            bean {
                val http: HttpSecurity = ref()
                OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
                http
                    .httpBasic()
                    .and()
                    .build()
            }

            bean {
                val http: HttpSecurity = ref()
                http
                    .authorizeRequests {
                        it.anyRequest().authenticated()
                    }
                    .httpBasic().and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                    .build()
            }

            bean {
                ProviderSettings
                    .builder()
                    .issuer(rootUri)
                    .build();
            }

            bean { BCryptPasswordEncoder() }

            bean {
                val encoder: PasswordEncoder = ref()

                val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("messaging-client")
                    .clientSecret(encoder.encode("secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .redirectUri("$rootUri/api/xxx")
                    .scope("efc")
                    .clientSettings(
                        ClientSettings.builder()
                            .requireAuthorizationConsent(false)
                            .requireProofKey(false)
                            .build())
                    .tokenSettings(
                        TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(60))
                            .refreshTokenTimeToLive(Duration.ofMinutes(120))
                            .build()
                    )
                    .build()

                InMemoryRegisteredClientRepository(registeredClient)
            }

            bean {
                val http: HttpSecurity = ref()
                http
                    .authorizeHttpRequests { authz ->
                        authz
                            .antMatchers("/secured/*")
                            .hasAuthority("SCOPE_efc")
                            .and()
                            .oauth2ResourceServer().jwt()
                    }
                    .build()
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