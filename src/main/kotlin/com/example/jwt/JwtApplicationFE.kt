package com.example.jwt

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.support.beans
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.RequestEntity
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2TokenType
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ClientSettings
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.exchange
import org.springframework.web.servlet.function.ServerResponse
import org.springframework.web.servlet.function.body
import org.springframework.web.servlet.function.router
import java.time.Duration
import java.util.*
import javax.servlet.http.HttpServletRequest


@SpringBootApplication
class JwtApplicationFE

fun main(args: Array<String>) {
    val hostname = "127.0.0.1"
    val port = "8080"
    val rootUri = "http://$hostname:$port"
    val issuerUri = "http://$hostname:$port"
    val tokenRoutes = "/oauth"
    val redirectUri = "$tokenRoutes/tokenCallback"
    val tokenUri = "$tokenRoutes/token"

    runApplication<JwtApplicationFE>(*args){
        addInitializers(beans {
            bean {
                val restTemplateBuilder: RestTemplateBuilder = ref()
                val rest = restTemplateBuilder.rootUri(rootUri).build()

                router {
                    POST(tokenUri){
                        val info = it.body<Map<String, String>>()
                        val clientId = it.principal().get().name
                        val authorizeUrl = "/oauth2/authorize?response_type=code&client_id=$clientId&scope=openid+efc&redirect_uri=$rootUri$redirectUri"

                        val username = info["username"]!!
                        val password = info["password"]!!

                        val headers = HttpHeaders().apply {
                            contentType = MediaType.APPLICATION_FORM_URLENCODED
                            setBasicAuth(username, password)
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
                            headers.add("client_id", clientId)

                            val secret = SecurityContextHolder.getContext().authentication.credentials.toString()

                            headers.add("secret", secret)
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

                        val clientId = it.headers().header("client_id")[0]
                        val secret = it.headers().header("secret")[0]

                        val headers = HttpHeaders().apply {
                            contentType = MediaType.APPLICATION_FORM_URLENCODED
                            setBasicAuth(clientId, secret)
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
                CurrentUserService {
                    val service: UserDetailsService = ref()
                    val principal = (SecurityContextHolder.getContext().authentication.name as String)
                    try {
                        service.loadUserByUsername(principal)
                    }catch (ex: Exception){
                        ex.printStackTrace()
                        throw ex
                    }
                }
            }

            bean {
                router {
                    GET("/secured/test") {
                        val userDetails: CurrentUserService = ref()
                        val name = userDetails.getUser().username
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
                val clientRepository: RegisteredClientRepository = ref()
                val passwordEncoder: PasswordEncoder = ref()
                http
                    .antMatcher(tokenUri)
                    .authenticationManager { auth ->
                        clientRepository.findByClientId(auth.name)
                            ?.let { client ->
                                if (!passwordEncoder.matches(auth.credentials.toString(), client.clientSecret))
                                    throw AuthenticationCredentialsNotFoundException("")
                                auth
                            }
                            ?: throw AuthenticationCredentialsNotFoundException("")
                    }
                    .httpBasic().and()
                    .csrf().ignoringAntMatchers(tokenUri).and()
                    .build()
            }

            bean {
                val http: HttpSecurity = ref()

                http
                    .authorizeHttpRequests { authz ->
                        authz
                            .antMatchers("/secured/*")
                            .hasAnyAuthority("SCOPE_efc")
                            .and()
                            .oauth2ResourceServer().jwt()
                    }
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                    .build()
            }

            bean {
                ProviderSettings
                    .builder()
                    .issuer(issuerUri)
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
                            .reuseRefreshTokens(false)
                            .accessTokenTimeToLive(Duration.ofMinutes(60))
                            .refreshTokenTimeToLive(Duration.ofMinutes(120))
                            .build()
                    )
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



@Configuration(proxyBeanMethods = false)
class MyConfigurationFE{

    @Bean
    fun jwtCustomizer() =
        OAuth2TokenCustomizer<JwtEncodingContext>{ context ->
            if (OAuth2TokenType.ACCESS_TOKEN == context.tokenType) {
                context.headers.type("JWT").build()

                val principal = context.getPrincipal<UsernamePasswordAuthenticationToken>()

                context.claims
                    .id(UUID.randomUUID().toString())
                    .claim("roles", principal.authorities.map { it.authority })
            }
        }
}

fun interface CurrentUserService {
    fun getUser(): UserDetails
}