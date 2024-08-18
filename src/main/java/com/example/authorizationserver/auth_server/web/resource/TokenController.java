package com.example.authorizationserver.auth_server.web.resource;

import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class TokenController {

    private final OAuth2AuthorizedClientService authorizedClientService;

//    @GetMapping("/loginSuccess")
//    public String getToken(OAuth2AuthorizedClient authorizedClient) {
//        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
//        // Use the access token to generate your own tokens
//        // e.g., JWT token creation logic
//        return "Token: " + accessToken.getTokenValue();
//    }

    @GetMapping("/loginSuccess")
    public String loginSuccess(@AuthenticationPrincipal OidcUser oidcUser, Authentication authentication) {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String username = oidcUser.getPreferredUsername();

        return "Login successful! Welcome, " + username;
    }
}
