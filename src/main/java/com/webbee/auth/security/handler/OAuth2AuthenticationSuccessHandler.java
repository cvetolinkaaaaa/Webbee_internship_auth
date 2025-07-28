package com.webbee.auth.security.handler;

import com.webbee.auth.entity.AuthType;
import com.webbee.auth.entity.Role;
import com.webbee.auth.entity.User;
import com.webbee.auth.repository.RoleRepository;
import com.webbee.auth.repository.UserRepository;
import com.webbee.auth.security.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Обработчик успешной OAuth2 аутентификации.
 * @author Evseeva Tsvetolina
 */
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    /**
     * Обрабатывает успешную OAuth2 аутентификацию.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        if (email == null) {
            throw new IllegalStateException("Email is null");
        }

        Optional<User> optionalUser = userRepository.findByEmail(email);

        User user;
        if (optionalUser.isPresent()) {
            user = optionalUser.get();

            if (AuthType.LOCAL.equals(user.getAuthType())) {
                throw new OAuth2AuthenticationException("User is already exist");
            }

        } else {
            Set<Role> roles = roleRepository.findByName("USER").stream().collect(Collectors.toSet());
            user = User.builder()
                    .username(name)
                    .email(email)
                    .password(null)
                    .roles(roles)
                    .authType(AuthType.GOOGLE)
                    .build();
            userRepository.save(user);
        }

        String token = jwtService.generateJwtToken(user);
        String targetUrl = "http://localhost:8080/redirect?token=" + token;
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

}
