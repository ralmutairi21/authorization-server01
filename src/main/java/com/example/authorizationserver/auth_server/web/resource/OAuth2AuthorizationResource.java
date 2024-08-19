package com.example.authorizationserver.auth_server.web.resource;

import com.example.authorizationserver.auth_server.core.domain.TokenServiceImp;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
@AllArgsConstructor
public class OAuth2AuthorizationResource {

    private final WebClient webClient;

    private final TokenServiceImp tokenService;

    @GetMapping("/login/oauth2/code/spring")
    public String handleOAuth2Callback(@RequestParam("code") String code, Model model) {
        OAuth2AccessTokenResponse keycloakTokenResponse = exchangeCodeForToken(code);

        String customToken = tokenService.generateToken(keycloakTokenResponse);
        model.addAttribute("token", customToken);
        return "success"; // or redirect to a different page or endpoint
    }

    private OAuth2AccessTokenResponse exchangeCodeForToken(String code) {
        return webClient.post()
                .uri("http://localhost:8080/auth/realms/auth-server/protocol/openid-connect/token")
                .headers(headers -> {
                    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                    headers.setBasicAuth("web-client", "secret"); // Your client credentials
                })
                .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                        .with("code", code)
                        .with("redirect_uri", "http://localhost:8082/login/oauth2/code/spring"))
                .retrieve()
                .bodyToMono(OAuth2AccessTokenResponse.class)
                .block(); // Use block to make the call synchronous
    }
}


