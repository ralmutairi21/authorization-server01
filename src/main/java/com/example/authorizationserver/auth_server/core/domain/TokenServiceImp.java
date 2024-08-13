package com.example.authorizationserver.auth_server.core.domain;

import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class TokenServiceImp implements TokenService {

}
