package com.webbee.auth.security.filter;

import com.webbee.auth.security.model.TokenAuthentication;
import com.webbee.auth.security.service.JwtService;
import com.webbee.auth.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Фильтр для обработки JWT.
 * Этот фильтр перехватывает все HTTP запросы и проверяет наличие JWT токена
 */
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String token = JwtUtils.parseToken(request);

        if (Optional.ofNullable(token).isPresent()) {
            if (jwtService.isTokenExpired(token)) {
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"Token has been expired\"}");
                return;
            }

            TokenAuthentication authentication = new TokenAuthentication(jwtService.parseToken(token));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }

}
