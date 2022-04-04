package com.example.jwt

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.context.support.beans
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.RequestEntity
import org.springframework.http.ResponseEntity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.config.ClientSettings
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.exchange
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
    val tokenRoutes = "/bla"
    val redirectUri = "$tokenRoutes/tokenCallback"
    val tokenUri = "$tokenRoutes/token"

    runApplication<JwtApplicationFE>(*args){
        addInitializers(beans {
            bean {
                val restTemplateBuilder: RestTemplateBuilder = ref()
                val rest = restTemplateBuilder.rootUri(rootUri).build()

                router {
                    POST(tokenUri){
                        val authorizeUrl = "/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid&redirect_uri=$rootUri$redirectUri&state=1234"

                        val headers = HttpHeaders().apply {
                            contentType = MediaType.APPLICATION_FORM_URLENCODED
                            setBasicAuth("user1", "password")
                        }
                        val request = RequestEntity
                            .get(authorizeUrl)
                            .headers(headers)
                            .build()

                        try {
                            rest.exchange<String>(request)
                        } catch (ex: HttpClientErrorException.NotFound){
                            val strings = ex.responseHeaders!!["Set-Cookie"]
                            headers.add("Cookie", strings!![0])
                            rest.exchange(RequestEntity
                                .get(authorizeUrl)
                                .headers(headers)
                                .build())
                        }.let { responseEntity ->
                            ServerResponse.ok()
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(responseEntity.body!!)
                        }
                    }

                    GET(redirectUri){
                        val code: String? = it.param("code").orElse(null)
                        val state: String? = it.param("state").orElse(null)

                        val headers = HttpHeaders().apply {
                            contentType = MediaType.APPLICATION_FORM_URLENCODED
                            setBasicAuth("messaging-client", "secret")
                        }
                        val obj: MultiValueMap<String, String> = LinkedMultiValueMap<String, String>().apply {
                            add("grant_type", "authorization_code")
                            add("code", code)
                            add("redirect_uri", "$rootUri$redirectUri")
                        }
                        val request = RequestEntity
                            .post("/oauth2/token")
                            .headers(headers)
                            .body(obj)

                        val responseEntity: ResponseEntity<String> = rest.exchange(request)

                        ServerResponse.ok()
                            .contentType(MediaType.APPLICATION_JSON)
                            .body(responseEntity.body!!)
                    }
                }
            }

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
                    .csrf().ignoringAntMatchers(tokenUri).and()
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
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("$rootUri$redirectUri")
                    .scope(OidcScopes.OPENID)
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