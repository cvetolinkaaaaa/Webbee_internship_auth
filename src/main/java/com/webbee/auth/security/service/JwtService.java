package com.webbee.auth.security.service;

import com.webbee.auth.security.model.CustomUserDetails;
import com.webbee.auth.security.model.TokenData;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Сервис для работы с JWT (JSON Web Token) в системе аутентификации и авторизации.
 * Предоставляет полный набор функций для работы с JWT токенами, включая генерацию,
 * парсинг, валидацию и извлечение пользовательских данных.
 */
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.life-time}")
    private Long lifeTime;

    /**
     * Создает подписанный JWT токен, содержащий информацию о пользователе,
     * его ролях и времени создания. Токен подписывается секретным ключом
     * и имеет ограниченное время жизни
     */
    public String generateJwtToken(CustomUserDetails userDetails, Long userId) {
        Map<String, Object> claims = buildClaims(userDetails, userId);
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + lifeTime);

        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(now)
                .expiration(expirationDate)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Формирует структуру данных, содержащую пользовательскую информацию
     * для включения в JWT токен
     */
    private Map<String, Object> buildClaims(CustomUserDetails userDetails, Long userId) {
        Map<String, Object> claims = new HashMap<>();
        Set<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        claims.put("username", userDetails.getUsername());
        claims.put("roles", roles);
        claims.put("userId", userId);
        return claims;
    }

    /**
    * Парсит JWT токен и извлекает структурированные данные пользователя.
    */
    public TokenData parseToken(String token) {
        validateTokenFormat(token);

        return TokenData.builder()
                .token(token)
                .username(getUserNameFromToken(token))
                .authorities(createAuthorities(getRolesFromToken(token)))
                .id(getUserIdFromToken(token))
                .build();
    }

    /**
     * Проверяет, истек ли срок действия JWT токена.
     *
     */
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = getAllClaimsFromToken(token).getExpiration();
            return expiration.before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid JWT token", e);
        }
    }


    public Long getUserIdFromToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return claims.get("userId", Long.class);
    }

    public String getUserNameFromToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return claims.getSubject();
    }

    public List<String> getRolesFromToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        Object roles = claims.get("roles");
        if (roles instanceof List) {
            return (List<String>) roles;
        }
        return Collections.emptyList();
    }

    private Claims getAllClaimsFromToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JWT token", e);
        }
    }

    private List<SimpleGrantedAuthority> createAuthorities(List<String> roles) {
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private void validateTokenFormat(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
    }

    private SecretKey getSigningKey() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(secretKey.getBytes(StandardCharsets.UTF_8));
            return Keys.hmacShaKeyFor(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error creating signing key", e);
        }
    }

}
