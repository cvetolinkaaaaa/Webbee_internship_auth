package com.webbee.auth.controller;

import jakarta.persistence.EntityNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Обработка ошибок "Сущность не найдена" (404)
     */
    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<Object> handleEntityNotFound(EntityNotFoundException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.NOT_FOUND.value());
        body.put("error", "Not Found");
        body.put("message", ex.getMessage());
        return new ResponseEntity<>(body, HttpStatus.NOT_FOUND);
    }

    /**
     * Обработка ошибок аутентификации (401)
     */
    @ExceptionHandler({BadCredentialsException.class, AuthenticationException.class})
    public ResponseEntity<Object> handleAuthenticationException(Exception ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.UNAUTHORIZED.value());
        body.put("error", "Unauthorized");
        body.put("message", "Invalid credentials");
        return new ResponseEntity<>(body, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Обработка ошибок JWT токена (401)
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Object> handleJwtException(IllegalArgumentException ex) {

        if (ex.getMessage() != null && ex.getMessage().toLowerCase().contains("jwt")) {
            Map<String, Object> body = new HashMap<>();
            body.put("timestamp", LocalDateTime.now());
            body.put("status", HttpStatus.UNAUTHORIZED.value());
            body.put("error", "Unauthorized");
            body.put("message", "Invalid or expired token");
            return new ResponseEntity<>(body, HttpStatus.UNAUTHORIZED);
        }


        return handleBadRequest(ex);
    }

    /**
     * Обработка ошибок "Некорректный запрос" (400)
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Object> handleBadRequest(RuntimeException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("error", "Bad Request");
        body.put("message", ex.getMessage());
        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    /**
     * Обработка ошибок доступа (403)
     */
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<Object> handleSecurityException(SecurityException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.FORBIDDEN.value());
        body.put("error", "Forbidden");
        body.put("message", "Access denied");
        return new ResponseEntity<>(body, HttpStatus.FORBIDDEN);
    }

    /**
     * Общая обработка ошибок (500)
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleException(Exception ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        body.put("error", "Internal Server Error");
        body.put("message", "An unexpected error occurred");
        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
