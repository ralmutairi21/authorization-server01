package com.example.authorizationserver.auth_server.core.actions;

import com.example.authorizationserver.auth_server.core.domain.TokenService;
import com.example.authorizationserver.common.annotation.Action;
import lombok.AllArgsConstructor;

@Action
@AllArgsConstructor
public class TokenAction {
    private final TokenService tokenService;
}
