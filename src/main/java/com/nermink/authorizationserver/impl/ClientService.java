package com.nermink.authorizationserver.impl;

import com.nermink.authorizationserver.domain.model.Client;
import com.nermink.authorizationserver.domain.model.ClientRedirectUrl;
import com.nermink.authorizationserver.domain.model.ClientScope;
import com.nermink.authorizationserver.domain.repository.ClientRedirectUrlRepository;
import com.nermink.authorizationserver.domain.repository.ClientRepository;
import com.nermink.authorizationserver.domain.repository.ClientScopeRepository;
import com.nermink.authorizationserver.dto.request.CreateClientRequest;
import com.nermink.authorizationserver.dto.response.ClientResponse;

import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ClientService implements RegisteredClientRepository {

  private final ClientRepository clientRepository;
  private final ClientRedirectUrlRepository clientRedirectUrlRepository;
  private final ClientScopeRepository clientScopeRepository;

  
	/*
	 * @Bean public RegisteredClientRepository registeredClientRepository() {
	 * RegisteredClient registeredClient =
	 * RegisteredClient.withId(UUID.randomUUID().toString()) .clientId("client")
	 * .clientSecret("{noop}123456")
	 * .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
	 * .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	 * .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
	 * .redirectUri("http://127.0.0.1:8080/login/oauth2/code/articles-client-oidc")
	 * .redirectUri("http://127.0.0.1:8080/authorized") .scope(OidcScopes.OPENID)
	 * .build();
	 * 
	 * return new InMemoryRegisteredClientRepository(registeredClient); }
	 */
  
  @Override
  public void save(RegisteredClient registeredClient) {
  }

  @Override
  public RegisteredClient findById(String id) {
    var client = this.clientRepository.findById(id).orElseThrow();
    return Client.toRegisteredClient(client);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    var client = this.clientRepository.findById(clientId).orElseThrow();
    return Client.toRegisteredClient(client);
  }

  public ClientResponse createClient(CreateClientRequest request) {
    var scopes = request.getScopes().stream().map(ClientScope::new).collect(Collectors.toSet());
    scopes.forEach(this.clientScopeRepository::save);

    var client = new Client(request);
    client.setScopes(scopes);
    this.clientRepository.save(client);

    client.setRedirectUris(request.getRedirectUris().stream()
        .map(url -> new ClientRedirectUrl(url, client))
        .collect(Collectors.toSet()));
    client.getRedirectUris().forEach(this.clientRedirectUrlRepository::save);

    return new ClientResponse(client);
  }
}
