// package br.com.ldap.spike.demo.config;

// import java.util.UUID;

// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.oauth2.core.AuthorizationGrantType;
// import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
// import org.springframework.security.oauth2.core.oidc.OidcScopes;
// import
// org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

// @Configuration
// public class OAuthServerConfig {
// RegisteredClient registeredClient =
// RegisteredClient.withId(UUID.randomUUID().toString())
// .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
// .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
// .scope(OidcScopes.OPENID)
// .build();
// }
