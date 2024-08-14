package com.example.authorizationserver.auth_server.web.resource;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/token")
@AllArgsConstructor
public class TokenController {


    @GetMapping("hello")
    public ResponseEntity<String> takeToken(@RequestHeader("Authorization") String token) {
        return ResponseEntity.ok().body("Hello ALl");
    }
}
