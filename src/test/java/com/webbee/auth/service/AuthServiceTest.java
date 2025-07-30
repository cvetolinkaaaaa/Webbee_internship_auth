package com.webbee.auth.service;

import com.webbee.auth.dto.AuthStatusDto;
import com.webbee.auth.dto.LoginRequest;
import com.webbee.auth.dto.RegistrationDto;
import com.webbee.auth.entity.Role;
import com.webbee.auth.entity.User;
import com.webbee.auth.repository.RoleRepository;
import com.webbee.auth.repository.UserRepository;
import com.webbee.auth.security.model.CustomUserDetails;
import com.webbee.auth.security.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationProvider authenticationProvider;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    private RegistrationDto validRegistrationDto;
    private LoginRequest validLoginRequest;
    private User testUser;
    private Role userRole;

    @BeforeEach
    void setUp() {
        validRegistrationDto = RegistrationDto.builder()
                .username("testuser")
                .email("test@example.com")
                .password("password123")
                .build();

        validLoginRequest = LoginRequest.builder()
                .username("testuser")
                .password("password123")
                .build();

        userRole = Role.builder()
                .id(1L)
                .name("USER")
                .build();

        testUser = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .roles(Set.of(userRole))
                .build();
    }

    @Test
    void shouldRegisterUserSuccessfully() {

        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        AuthStatusDto result = authService.registration(validRegistrationDto);
        assertThat(result.getCode()).isEqualTo(HttpStatus.OK.value());
        verify(userRepository).save(any(User.class));
        verify(passwordEncoder).encode("password123");

    }

    @Test
    void shouldRejectRegistrationWithInvalidEmail() {

        RegistrationDto invalidEmailDto = RegistrationDto.builder()
                .username("testuser")
                .email("invalid-email")
                .password("password123")
                .build();
        AuthStatusDto result = authService.registration(invalidEmailDto);
        assertThat(result.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        verify(userRepository, never()).save(any(User.class));

    }

    @Test
    void shouldRejectRegistrationWithNullEmail() {

        RegistrationDto nullEmailDto = RegistrationDto.builder()
                .username("testuser")
                .email(null)
                .password("password123")
                .build();
        AuthStatusDto result = authService.registration(nullEmailDto);
        assertThat(result.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        verify(userRepository, never()).save(any(User.class));

    }

    @Test
    void shouldRejectRegistrationWithEmptyEmail() {

        RegistrationDto emptyEmailDto = RegistrationDto.builder()
                .username("testuser")
                .email("")
                .password("password123")
                .build();
        AuthStatusDto result = authService.registration(emptyEmailDto);
        assertThat(result.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        verify(userRepository, never()).save(any(User.class));

    }

    @Test
    void shouldRejectRegistrationWhenUsernameExists() {

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        AuthStatusDto result = authService.registration(validRegistrationDto);
        assertThat(result.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        verify(userRepository, never()).save(any(User.class));

    }

    @Test
    void shouldRejectRegistrationWhenEmailExists() {

        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        AuthStatusDto result = authService.registration(validRegistrationDto);
        assertThat(result.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        verify(userRepository, never()).save(any(User.class));

    }

    @Test
    void shouldHandleEmailWithSpacesDuringRegistration() {

        RegistrationDto emailWithSpacesDto = RegistrationDto.builder()
                .username("testuser")
                .email("  test@example.com  ")
                .password("password123")
                .build();
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        AuthStatusDto result = authService.registration(emailWithSpacesDto);
        assertThat(result.getCode()).isEqualTo(HttpStatus.OK.value());

    }

    @Test
    void shouldLoginSuccessfully() {

        Collection<? extends GrantedAuthority> authorities = testUser.getRoles().stream()
                .map(role -> (GrantedAuthority) () -> "ROLE_" + role.getName())
                .collect(Collectors.toList());
        CustomUserDetails userDetails = new CustomUserDetails(
                testUser.getId(),
                testUser.getUsername(),
                testUser.getPassword(),
                authorities,
                testUser.getEmail()
        );
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(authenticationProvider.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(jwtService.generateJwtToken(eq(userDetails), eq(1L))).thenReturn("jwt-token");
        AuthStatusDto result = authService.login(validLoginRequest);
        assertThat(result.getCode()).isEqualTo(HttpStatus.OK.value());
        assertThat(result.getToken()).isEqualTo("jwt-token");

    }

    @Test
    void shouldRejectLoginWithInvalidCredentials() {

        when(authenticationProvider.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));
        AuthStatusDto result = authService.login(validLoginRequest);
        assertThat(result.getCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(result.getToken()).isNull();

    }

    @Test
    void shouldValidateCorrectEmailFormats() {

        String[] validEmails = {
                "test@example.com",
                "user.name@domain.co.uk",
                "user+tag@example.org",
                "123@domain.com",
                "test_email@example-domain.com"
        };
        for (String email : validEmails) {

            reset(userRepository, roleRepository, passwordEncoder);
            RegistrationDto dto = RegistrationDto.builder()
                    .username("testuser" + email.hashCode())
                    .email(email)
                    .password("password123")
                    .build();
            when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
            when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
            when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
            when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
            when(userRepository.save(any(User.class))).thenReturn(testUser);
            AuthStatusDto result = authService.registration(dto);
            assertThat(result.getCode())
                    .as("Email %s should be valid", email)
                    .isEqualTo(HttpStatus.OK.value());
        }

    }

    @Test
    void shouldRejectInvalidEmailFormats() {

        String[] invalidEmails = {
                "invalid-email",
                "@domain.com",
                "user@",
                "user@domain",
                "user.domain.com",
                "user@domain.",
                ""

        };

        for (String email : invalidEmails) {

            RegistrationDto dto = RegistrationDto.builder()
                    .username("testuser")
                    .email(email)
                    .password("password123")
                    .build();
            AuthStatusDto result = authService.registration(dto);
            assertThat(result.getCode())
                    .as("Email %s should be invalid", email)
                    .isEqualTo(HttpStatus.BAD_REQUEST.value());
        }

    }

    @Test
    void shouldRejectNullEmailInValidation() {

        RegistrationDto dto = RegistrationDto.builder()
                .username("testuser")
                .email(null)
                .password("password123")
                .build();
        AuthStatusDto result = authService.registration(dto);
        assertThat(result.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

    }

}