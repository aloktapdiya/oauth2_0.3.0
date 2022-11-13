package com.nermink.authorizationserver.config;

import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;

import com.nermink.authorizationserver.impl.ClientService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@RequiredArgsConstructor
public class Oauth2Config {

  private final ClientService clientService;

  @Bean
  @Order(HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    http
        // Redirect to the login page when not authenticated from the
        // authorization endpoint
        .exceptionHandling((exceptions) -> exceptions
            .authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login"))
        );


    return http.build();
  }

//	@Bean
//	public RegisteredClientRepository registeredClientRepository() {
//		// @formatter:off
//		RegisteredClient loginClient = RegisteredClient.withId(UUID.randomUUID().toString())
//				.clientId("login-client")
//				.clientSecret("{noop}openid-connect")
//				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/login-client")
//				.redirectUri("http://127.0.0.1:8080/authorized")
//				.scope(OidcScopes.OPENID)
//				.scope(OidcScopes.PROFILE)
//				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//				.build();
//		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//				.clientId("messaging-client")
//				.clientSecret("{noop}secret")
//				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//				.scope("message:read")
//				.scope("message:write")
//				.build();
//		// @formatter:on
//
//		return new InMemoryRegisteredClientRepository(loginClient, registeredClient);
//	}
//	
//	
	@Bean
	public JwtDecoder jwtDecoder(KeyPair keyPair) {
		return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
	}  
  
  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }
  @Bean
  public TokenSettings tokenSettings() {
    //@formatter:off
    return TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofMinutes(30L))
        .build();
    // @formatter:on
  }
  @Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

//  @Bean
//  public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
//    // @formatter:off
//    RegisteredClient registeredClient = RegisteredClient.withId("e4a295f7-0a5f-4cbc-bcd3-d870243d1b05")
//        .clientId("client")
//        .clientSecret("{noop}123")
//        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
//        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//        .tokenSettings(tokenSettings())
//        .build();
//    // @formatter:on
//
//    JdbcRegisteredClientRepository registeredClientRepository =
//        new JdbcRegisteredClientRepository(jdbcTemplate);
//    registeredClientRepository.save(registeredClient);
//
//    return registeredClientRepository;
//  }  
  
  
  
  @Bean
  public ProviderSettings providerSettings() {
	    return ProviderSettings.builder()
	            .issuer("http://localhost:8080")
	            .build();  }

}
