# Legacy Jwt access flow

How to get an access token (`/oauth2/token` endpoint) using then new [spring-authorization-server](https://github.com/spring-projects/spring-authorization-server).
In contrast to the `@EnableAuthorizationServer` that [has been deprecated](https://docs.spring.io/spring-security/oauth/site/docs/2.4.0.RELEASE/apidocs/org/springframework/security/oauth2/config/annotation/web/configuration/EnableAuthorizationServer.html) 

### Notes

 * Everything is implemented in the file `JwtApplication.kt` using the `bean` DSL (it's the same of using `@Configuration(proxyBeanMethods = false)` and `@Bean`).
 * the default token endpoint is `/oauth2/token` (can be changed using `ProviderSettings`)
 * The **`password` grant_type** is [not anymore implemented](https://github.com/spring-projects/spring-authorization-server/issues/126)
 * The **refresh token** is [not given back](https://github.com/spring-projects/spring-authorization-server/pull/335) when you get an access token with the `client_credentials` grant_type. 
   You must use authorization_code grant type to get a refresh token  
