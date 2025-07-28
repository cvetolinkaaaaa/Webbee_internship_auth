package com.webbee.auth.security.model;

import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@Getter
public class TokenAuthentication extends UsernamePasswordAuthenticationToken {

    private TokenData tokenData;

    public TokenAuthentication(TokenData tokenData) {
        super(tokenData.getUsername(), null, tokenData.getAuthorities());
        this.tokenData = tokenData;
    }

}
