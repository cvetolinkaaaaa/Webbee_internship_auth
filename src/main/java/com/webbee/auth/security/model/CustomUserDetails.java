package com.webbee.auth.security.model;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * Реализация интерфейса UserDetails для Spring Security.
 * Представляет детали аутентифицированного пользователя в контексте Spring Security.
 */
public class CustomUserDetails implements UserDetails {

    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    @Getter
    private String email;

    public CustomUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities, String email) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
        this.email = email;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
