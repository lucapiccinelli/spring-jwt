# Legacy Jwt access token flow

How to get an access token (`/oauth2/token` endpoint) using then new [spring-authorization-server](https://github.com/spring-projects/spring-authorization-server).
In contrast to the `@EnableAuthorizationServer` that [has been deprecated](https://docs.spring.io/spring-security/oauth/site/docs/2.4.0.RELEASE/apidocs/org/springframework/security/oauth2/config/annotation/web/configuration/EnableAuthorizationServer.html) 

### Notes

 * Everything is implemented in the file [`JwtApplication.kt`](src/main/kotlin/com/example/jwt/JwtApplication.kt) using the `bean` DSL (it's the same of using `@Configuration(proxyBeanMethods = false)` and `@Bean`).
 * The default token endpoint is `/oauth2/token` (can be changed using `ProviderSettings`)
 * The **`password` grant_type** is [not anymore implemented](https://github.com/spring-projects/spring-authorization-server/issues/126)
 * The **refresh token** is [not given back](https://github.com/spring-projects/spring-authorization-server/pull/335) when you get an access token with the `client_credentials` grant_type. 
   You must use authorization_code grant type to get a refresh token
 * The grant type `client_credentials` doesn't check for a username and password. This is why i implemented it [with a filter](https://github.com/lucapiccinelli/spring-jwt/blob/f4efd924e708c272715581d88f8277f989e7239f/src/main/kotlin/com/example/jwt/JwtApplication.kt#L77)
 * I didn't understand why the `OAuth2TokenCustomizer` doesn't get resolved if i put it in the context using `bean{}` [instead of](https://github.com/lucapiccinelli/spring-jwt/blob/19228cb560a8a4af61be0ef5d18d73a0bbc232e8/src/main/kotlin/com/example/jwt/JwtApplication.kt#L207) `@Bean`
 * put this line in your **file hosts**
 ```
127.0.0.1 auth-server
```
