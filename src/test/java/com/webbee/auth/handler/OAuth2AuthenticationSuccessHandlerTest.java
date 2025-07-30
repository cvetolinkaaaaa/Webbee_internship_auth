package com.webbee.auth.handler;

import com.webbee.auth.entity.AuthType;
import com.webbee.auth.entity.Role;
import com.webbee.auth.entity.User;
import com.webbee.auth.repository.RoleRepository;
import com.webbee.auth.repository.UserRepository;
import com.webbee.auth.security.handler.OAuth2AuthenticationSuccessHandler;
import com.webbee.auth.security.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.RedirectStrategy;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2AuthenticationSuccessHandlerTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private Authentication authentication;

    @Mock
    private OAuth2User oAuth2User;

    @Mock
    private RedirectStrategy redirectStrategy;

    @InjectMocks
    private OAuth2AuthenticationSuccessHandler handler;

    private Role userRole;
    private User existingGoogleUser;
    private User existingLocalUser;

    @BeforeEach
    void setUp() {

        userRole = Role.builder()
                .id(1L)
                .name("USER")
                .build();
        existingGoogleUser = User.builder()
                .id(1L)
                .username("John Doe")
                .email("john.doe@gmail.com")
                .authType(AuthType.GOOGLE)
                .roles(Set.of(userRole))
                .build();
        existingLocalUser = User.builder()
                .id(2L)
                .username("jane.doe")
                .email("jane.doe@gmail.com")
                .password("hashedPassword")
                .authType(AuthType.LOCAL)
                .roles(Set.of(userRole))
                .build();
        handler.setRedirectStrategy(redirectStrategy);

    }

    @Test
    @DisplayName("Успешная аутентификация нового пользователя - создание учетной записи")
    void onAuthenticationSuccess_NewUser_CreatesUserAccount() throws IOException {

        String email = "new.user@gmail.com";
        String name = "New User";
        String generatedToken = "jwt-token-12345";
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("email", email);
        attributes.put("name", name);
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(oAuth2User.getAttribute("email")).thenReturn(email);
        when(oAuth2User.getAttribute("name")).thenReturn(name);
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(jwtService.generateJwtToken(any(User.class))).thenReturn(generatedToken);
        handler.onAuthenticationSuccess(request, response, authentication);
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getUsername()).isEqualTo(name);
        assertThat(savedUser.getEmail()).isEqualTo(email);
        assertThat(savedUser.getPassword()).isNull();
        assertThat(savedUser.getAuthType()).isEqualTo(AuthType.GOOGLE);
        assertThat(savedUser.getRoles()).containsExactly(userRole);
        verify(jwtService).generateJwtToken(savedUser);
        verify(redirectStrategy).sendRedirect(
                eq(request),
                eq(response),
                eq("http://localhost:8080/redirect?token=" + generatedToken)
        );

    }

    @Test
    @DisplayName("Успешная аутентификация существующего Google пользователя")
    void onAuthenticationSuccess_ExistingGoogleUser_UsesExistingAccount() throws IOException {

        String email = "john.doe@gmail.com";
        String name = "John Doe";
        String generatedToken = "jwt-token-67890";
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(oAuth2User.getAttribute("email")).thenReturn(email);
        when(oAuth2User.getAttribute("name")).thenReturn(name);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(existingGoogleUser));
        when(jwtService.generateJwtToken(existingGoogleUser)).thenReturn(generatedToken);
        handler.onAuthenticationSuccess(request, response, authentication);
        verify(userRepository, never()).save(any(User.class));
        verify(roleRepository, never()).findByName("USER");
        verify(jwtService).generateJwtToken(existingGoogleUser);
        verify(redirectStrategy).sendRedirect(
                eq(request),
                eq(response),
                eq("http://localhost:8080/redirect?token=" + generatedToken)
        );

    }

    @Test
    @DisplayName("Конфликт - попытка OAuth2 входа с email существующего LOCAL пользователя")
    void onAuthenticationSuccess_ExistingLocalUser_ThrowsException() {

        String email = "jane.doe@gmail.com";
        String name = "Jane Doe";
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(oAuth2User.getAttribute("email")).thenReturn(email);
        when(oAuth2User.getAttribute("name")).thenReturn(name);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(existingLocalUser));
        assertThatThrownBy(() -> handler.onAuthenticationSuccess(request, response, authentication))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(exception -> {
                    OAuth2AuthenticationException oAuth2Exception = (OAuth2AuthenticationException) exception;
                    assertThat(oAuth2Exception.getError().getErrorCode()).isEqualTo("User is already exist");
                });
        verify(userRepository, never()).save(any(User.class));
        verify(jwtService, never()).generateJwtToken(any(User.class));

    }

    @Test
    @DisplayName("Ошибка - отсутствует email в OAuth2 ответе")
    void onAuthenticationSuccess_NullEmail_ThrowsException() {

        String name = "User Without Email";
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(oAuth2User.getAttribute("email")).thenReturn(null);
        when(oAuth2User.getAttribute("name")).thenReturn(name);
        assertThatThrownBy(() -> handler.onAuthenticationSuccess(request, response, authentication))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Email is null");
        verify(userRepository, never()).findByEmail(any());
        verify(userRepository, never()).save(any(User.class));
        verify(jwtService, never()).generateJwtToken(any(User.class));

    }

    @Test
    @DisplayName("Создание нового пользователя с пустым именем")
    void onAuthenticationSuccess_NewUserWithNullName_CreatesUserWithNullName() throws IOException {

        String email = "user.no.name@gmail.com";
        String generatedToken = "jwt-token-null-name";
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(oAuth2User.getAttribute("email")).thenReturn(email);
        when(oAuth2User.getAttribute("name")).thenReturn(null);
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(jwtService.generateJwtToken(any(User.class))).thenReturn(generatedToken);
        handler.onAuthenticationSuccess(request, response, authentication);
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getUsername()).isNull();
        assertThat(savedUser.getEmail()).isEqualTo(email);
        assertThat(savedUser.getAuthType()).isEqualTo(AuthType.GOOGLE);

    }

    @Test
    @DisplayName("Создание нового пользователя с пустым именем (строка)")
    void onAuthenticationSuccess_NewUserWithEmptyName_CreatesUserWithEmptyName() throws IOException {

        String email = "user.empty.name@gmail.com";
        String name = "";
        String generatedToken = "jwt-token-empty-name";
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(oAuth2User.getAttribute("email")).thenReturn(email);
        when(oAuth2User.getAttribute("name")).thenReturn(name);
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(jwtService.generateJwtToken(any(User.class))).thenReturn(generatedToken);
        handler.onAuthenticationSuccess(request, response, authentication);
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getUsername()).isEmpty();
        assertThat(savedUser.getEmail()).isEqualTo(email);

    }

    @Test
    @DisplayName("Обработка ситуации когда роль USER не найдена")
    void onAuthenticationSuccess_UserRoleNotFound_CreatesUserWithEmptyRoles() throws IOException {

        String email = "user.no.role@gmail.com";
        String name = "User No Role";
        String generatedToken = "jwt-token-no-role";
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(oAuth2User.getAttribute("email")).thenReturn(email);
        when(oAuth2User.getAttribute("name")).thenReturn(name);
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(roleRepository.findByName("USER")).thenReturn(Optional.empty());
        when(jwtService.generateJwtToken(any(User.class))).thenReturn(generatedToken);
        handler.onAuthenticationSuccess(request, response, authentication);
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getRoles()).isEmpty();

    }

    @Test
    @DisplayName("Проверка корректности формирования URL для редиректа")
    void onAuthenticationSuccess_RedirectUrlFormat_IsCorrect() throws IOException {

        String email = "test.redirect@gmail.com";
        String name = "Test Redirect";
        String generatedToken = "test-jwt-token-with-special-chars!@#$%";
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(oAuth2User.getAttribute("email")).thenReturn(email);
        when(oAuth2User.getAttribute("name")).thenReturn(name);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(existingGoogleUser));
        when(jwtService.generateJwtToken(existingGoogleUser)).thenReturn(generatedToken);
        handler.onAuthenticationSuccess(request, response, authentication);
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(redirectStrategy).sendRedirect(eq(request), eq(response), urlCaptor.capture());
        String redirectUrl = urlCaptor.getValue();
        assertThat(redirectUrl).isEqualTo("http://localhost:8080/redirect?token=" + generatedToken);

    }

    @Test
    @DisplayName("Проверка вызова методов в правильном порядке для нового пользователя")
    void onAuthenticationSuccess_NewUser_CallsMethodsInCorrectOrder() throws IOException {

        String email = "order.test@gmail.com";
        String name = "Order Test";
        String generatedToken = "order-test-token";
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(oAuth2User.getAttribute("email")).thenReturn(email);
        when(oAuth2User.getAttribute("name")).thenReturn(name);
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(jwtService.generateJwtToken(any(User.class))).thenReturn(generatedToken);
        handler.onAuthenticationSuccess(request, response, authentication);
        InOrder inOrder = inOrder(authentication, oAuth2User, userRepository, roleRepository, jwtService, redirectStrategy);
        inOrder.verify(authentication).getPrincipal();
        inOrder.verify(oAuth2User).getAttribute("email");
        inOrder.verify(oAuth2User).getAttribute("name");
        inOrder.verify(userRepository).findByEmail(email);
        inOrder.verify(roleRepository).findByName("USER");
        inOrder.verify(userRepository).save(any(User.class));
        inOrder.verify(jwtService).generateJwtToken(any(User.class));
        inOrder.verify(redirectStrategy).sendRedirect(any(), any(), any());

    }

    @Test
    @DisplayName("Проверка вызова методов в правильном порядке для существующего пользователя")
    void onAuthenticationSuccess_ExistingUser_CallsMethodsInCorrectOrder() throws IOException {

        String email = "existing.order@gmail.com";
        String name = "Existing Order";
        String generatedToken = "existing-order-token";
        when(authentication.getPrincipal()).thenReturn(oAuth2User);
        when(oAuth2User.getAttribute("email")).thenReturn(email);
        when(oAuth2User.getAttribute("name")).thenReturn(name);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(existingGoogleUser));
        when(jwtService.generateJwtToken(existingGoogleUser)).thenReturn(generatedToken);
        handler.onAuthenticationSuccess(request, response, authentication);
        InOrder inOrder = inOrder(authentication, oAuth2User, userRepository, jwtService, redirectStrategy);
        inOrder.verify(authentication).getPrincipal();
        inOrder.verify(oAuth2User).getAttribute("email");
        inOrder.verify(oAuth2User).getAttribute("name");
        inOrder.verify(userRepository).findByEmail(email);
        inOrder.verify(jwtService).generateJwtToken(existingGoogleUser);
        inOrder.verify(redirectStrategy).sendRedirect(any(), any(), any());
        verify(roleRepository, never()).findByName(any());
        verify(userRepository, never()).save(any(User.class));

    }

}
