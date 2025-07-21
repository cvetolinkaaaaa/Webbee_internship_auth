package com.webbee.auth.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

/**
 * Класс для получения токена из заголовка.
 */
public final class JwtUtils {

    private JwtUtils() {}

    public static String parseToken(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        return StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ") ? headerAuth.substring(7) : null;
    }

}
