package com.example.authorizationserver.auth_server.common.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.StringUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class TokenConfiguration {


//    @Bean
//    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(
//            OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer
//    ) {
//        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
//        accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
//        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
//
//        return new DelegatingOAuth2TokenGenerator(
//                accessTokenGenerator, refreshTokenGenerator
//        );
//    }
//
//    @Bean
//    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer () {
//        return context -> {
//            UserDetails userDetails = null;
//
//            if (context.getPrincipal() instanceof OAuth2ClientAuthenticationToken) {
//                userDetails = (UserDetails) context.getPrincipal().getDetails();
//            } else if (context.getPrincipal() instanceof AbstractAuthenticationToken) {
//                userDetails = (UserDetails) context.getPrincipal().getPrincipal();
//            } else {
//                throw new IllegalStateException("Unexpected token type");
//            }
//
//
//            context.getClaims()
//                    .claim(
//                            "username", "tesstt"
//                    );
//        };
//    }
}

