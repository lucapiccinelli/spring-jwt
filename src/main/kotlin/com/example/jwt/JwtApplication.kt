package com.example.jwt

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import io.konad.plus
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.support.beans
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2TokenType
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.oauth2.server.authorization.config.TokenSettings
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.web.servlet.function.ServerResponse
import org.springframework.web.servlet.function.router
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Principal
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletResponse


@SpringBootApplication
class JwtApplication

fun main(args: Array<String>) {
    runApplication<JwtApplication>(*args){
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

                val userAndPasswordFilter: (ServletRequest, ServletResponse, FilterChain) -> Unit = { req: ServletRequest, resp, chain ->
                    try {
                        val username: String? = req.getParameter("username")
                        val password: String? = req.getParameter("password")
                        val passwordEncoder: PasswordEncoder = ref()
                        val userDetailsService: UserDetailsService = ref()

                        val matchUser: (String, String) -> Unit = { u, p ->
                            val user = userDetailsService.loadUserByUsername(u)
                            if (!passwordEncoder.matches(p, user.password)) {
                                throw BadCredentialsException("wrong credentials")
                            }
                        }

                        (matchUser + username + password)
                            ?: throw BadCredentialsException("missing username or password")

                        chain.doFilter(req, resp)
                    } catch (ex: AuthenticationException) {
                        resp as HttpServletResponse
                        resp.status = HttpStatus.UNAUTHORIZED.value()
                        ex.message?.let { resp.writer.write(it) }
                    }
                }

                http.addFilterAfter(userAndPasswordFilter, BasicAuthenticationFilter::class.java)
                val build: DefaultSecurityFilterChain = http.build()
                build
            }

            bean {
                val http: HttpSecurity = ref()
                http.authorizeHttpRequests { authz ->
                    authz
                        .antMatchers("/secured/*")
                        .hasRole("USER")
                        .and()
                        .oauth2ResourceServer()
                        .jwt{ jwtConfigurer ->
                            jwtConfigurer.jwtAuthenticationConverter { jwt ->
                                val roles: List<String>? = jwt.getClaimAsStringList("roles")
                                JwtAuthenticationToken(jwt, roles?.map(::SimpleGrantedAuthority))
                            }
                        }
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

@Configuration(proxyBeanMethods = false)
class MyConfiguration{

    @Bean
    fun jwtCustomizer(userDetailsService: UserDetailsService) =
        OAuth2TokenCustomizer<JwtEncodingContext>{ context ->
            if (OAuth2TokenType.ACCESS_TOKEN == context.tokenType) {
                context.headers.type("JWT").build()

                val username = context
                    .getAuthorizationGrant<OAuth2ClientCredentialsAuthenticationToken>()
                    .additionalParameters["username"]
                    ?.toString()

                context.claims
                    .subject(username)
                    .claim("roles", "ROLE_USER")
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