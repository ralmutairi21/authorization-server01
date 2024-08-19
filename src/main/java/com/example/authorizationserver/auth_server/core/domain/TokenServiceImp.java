package com.example.authorizationserver.auth_server.core.domain;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@AllArgsConstructor
public class TokenServiceImp implements TokenService {

    public String generateToken(OAuth2AccessTokenResponse keycloakTokenResponse) {
        // Extract the access token from Keycloak's response
        String keycloakAccessToken = keycloakTokenResponse.getAccessToken().getTokenValue();

        // Logic to create a custom token, for example, a JWT with additional claims
        // Here, I'm just returning the Keycloak token as an example
        // In a real application, you'd likely sign a new JWT with custom claims

        return keycloakAccessToken;  // Replace with your own custom token generation logic
    }
}
