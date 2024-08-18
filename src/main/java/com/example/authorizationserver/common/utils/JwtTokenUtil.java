package com.example.authorizationserver.common.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtTokenUtil {

    private String secretKey = "your-secret-key";

    public String generateToken(String subject) {
        return Jwts.builder()
                .setSubject(subject)
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }
}
