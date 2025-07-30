package com.webbee.auth.service;

import com.webbee.auth.dto.AuthStatusDto;
import com.webbee.auth.dto.LoginRequest;
import com.webbee.auth.dto.RegistrationDto;
import com.webbee.auth.entity.AuthType;
import com.webbee.auth.entity.Role;
import com.webbee.auth.entity.User;
import com.webbee.auth.repository.RoleRepository;
import com.webbee.auth.repository.UserRepository;
import com.webbee.auth.security.model.CustomUserDetails;
import com.webbee.auth.security.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Сервис аутентификации и регистрации пользователей в системе.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AuthenticationProvider authenticationProvider;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );

    /**
     * Регистрирует нового пользователя в системе.
     * регистрация нового пользователя, включая
     * валидацию входных данных, проверку уникальности, хеширование пароля
     * и назначение базовых ролей
     */
    @Transactional
    public AuthStatusDto registration(RegistrationDto request) {
        if (!isEmailValid(request.getEmail())) {
            return createErrorResponse();
        }

        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return createErrorResponse();
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            return createErrorResponse();
        }

        Set<Role> roles = roleRepository.findByName("USER")
                .stream()
                .collect(Collectors.toSet());

        userRepository.save(User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .authType(AuthType.LOCAL)
                .roles(roles)
                .build()
        );

        return createSuccessResponse();
    }

    /**
     * Выполняет аутентификацию пользователя и выдает JWT токен.
     * вход пользователя в систему, включая
     * проверку учетных данных и генерацию JWT токена
     * для последующего использования в запросах.
     */
    @Transactional(readOnly = true)
    public AuthStatusDto login(LoginRequest request) {
        try {
            Authentication authentication = authenticationProvider.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            Long userId = userDetails.getId();
            String token = jwtService.generateJwtToken(userDetails, userId);
            return AuthStatusDto.builder()
                    .code(HttpStatus.OK.value())
                    .token(token)
                    .build();
        } catch (AuthenticationException e) {
            return AuthStatusDto.builder()
                    .code(HttpStatus.FORBIDDEN.value())
                    .build();
        }
    }

    private AuthStatusDto createErrorResponse() {
        return AuthStatusDto.builder()
                .code(HttpStatus.BAD_REQUEST.value())
                .build();
    }

    private AuthStatusDto createSuccessResponse() {
        return AuthStatusDto.builder()
                .code(HttpStatus.OK.value())
                .build();
    }

    private boolean isEmailValid(String email) {
        if (email == null || email.isEmpty()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email.trim()).matches();
    }

}
