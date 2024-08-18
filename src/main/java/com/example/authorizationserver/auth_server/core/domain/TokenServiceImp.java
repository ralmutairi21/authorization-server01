package com.example.authorizationserver.auth_server.core.domain;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@AllArgsConstructor
public class TokenServiceImp implements TokenService {

    private final String secretKey = "your-secret-key"; // Replace with your secret key
    private final long expirationTime = 3600_000; // 1 hour in milliseconds

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "USER"); // Example of adding a custom claim

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }
}
