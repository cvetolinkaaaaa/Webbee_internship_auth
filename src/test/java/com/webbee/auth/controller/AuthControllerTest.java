package com.webbee.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webbee.auth.TestSecurityConfig;
import com.webbee.auth.dto.AuthStatusDto;
import com.webbee.auth.dto.LoginRequest;
import com.webbee.auth.dto.RegistrationDto;
import com.webbee.auth.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@TestPropertySource(properties = {
    "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration," +
    "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration," +
    "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration",
    "jwt.secret=TestSecret",
    "spring.liquibase.enabled=false",
    "spring.jpa.hibernate.ddl-auto=none"
})
@Import(TestSecurityConfig.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("PUT /auth/signup - успешная регистрация пользователя")
    void signUp_ValidRequest_ReturnsSuccess() throws Exception {

        RegistrationDto registrationDto = RegistrationDto.builder()
                .username("testuser")
                .password("password123")
                .email("test@example.com")
                .build();
        AuthStatusDto response = AuthStatusDto.builder()
                .code(HttpStatus.OK.value())
                .token("jwt-token")
                .build();
        when(authService.registration(any(RegistrationDto.class))).thenReturn(response);
        mockMvc.perform(put("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationDto)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.token").value("jwt-token"));
        verify(authService).registration(any(RegistrationDto.class));

    }

    @Test
    @DisplayName("PUT /auth/signup - ошибка регистрации - email уже занят")
    void signUp_EmailAlreadyExists_ReturnsBadRequest() throws Exception {

        RegistrationDto registrationDto = RegistrationDto.builder()
                .username("testuser")
                .password("password123")
                .email("existing@example.com")
                .build();
        AuthStatusDto response = AuthStatusDto.builder()
                .code(HttpStatus.BAD_REQUEST.value())
                .token(null)
                .build();
        when(authService.registration(any(RegistrationDto.class))).thenReturn(response);
        mockMvc.perform(put("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationDto)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value(400))
                .andExpect(jsonPath("$.token").isEmpty());
        verify(authService).registration(any(RegistrationDto.class));

    }

    @Test
    @DisplayName("PUT /auth/signup - ошибка регистрации - username уже занят")
    void signUp_UsernameAlreadyExists_ReturnsBadRequest() throws Exception {

        RegistrationDto registrationDto = RegistrationDto.builder()
                .username("existinguser")
                .password("password123")
                .email("test@example.com")
                .build();
        AuthStatusDto response = AuthStatusDto.builder()
                .code(HttpStatus.BAD_REQUEST.value())
                .token(null)
                .build();
        when(authService.registration(any(RegistrationDto.class))).thenReturn(response);
        mockMvc.perform(put("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationDto)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value(400));
        verify(authService).registration(any(RegistrationDto.class));

    }

    @Test
    @DisplayName("POST /auth/signin - успешная аутентификация")
    void signIn_ValidCredentials_ReturnsSuccess() throws Exception {

        LoginRequest loginRequest = LoginRequest.builder()
                .username("testuser")
                .password("password123")
                .build();
        AuthStatusDto response = AuthStatusDto.builder()
                .code(HttpStatus.OK.value())
                .token("jwt-token")
                .build();
        when(authService.login(any(LoginRequest.class))).thenReturn(response);
        mockMvc.perform(post("/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(header().string("Authorization", "Bearer jwt-token"))
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.token").value("jwt-token"));
        verify(authService).login(any(LoginRequest.class));

    }

    @Test
    @DisplayName("POST /auth/signin - неправильные учетные данные")
    void signIn_InvalidCredentials_ReturnsForbidden() throws Exception {

        LoginRequest loginRequest = LoginRequest.builder()
                .username("testuser")
                .password("wrongpassword")
                .build();
        AuthStatusDto response = AuthStatusDto.builder()
                .code(HttpStatus.FORBIDDEN.value())
                .token(null)
                .build();
        when(authService.login(any(LoginRequest.class))).thenReturn(response);
        mockMvc.perform(post("/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value(403))
                .andExpect(jsonPath("$.token").isEmpty());
        verify(authService).login(any(LoginRequest.class));

    }

    @Test
    @DisplayName("POST /auth/signin - несуществующий пользователь")
    void signIn_NonExistentUser_ReturnsForbidden() throws Exception {

        LoginRequest loginRequest = LoginRequest.builder()
                .username("nonexistent")
                .password("password123")
                .build();
        AuthStatusDto response = AuthStatusDto.builder()
                .code(HttpStatus.FORBIDDEN.value())
                .token(null)
                .build();
        when(authService.login(any(LoginRequest.class))).thenReturn(response);
        mockMvc.perform(post("/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value(403));
        verify(authService).login(any(LoginRequest.class));

    }

}