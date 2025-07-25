package com.webbee.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webbee.auth.TestSecurityConfig;
import com.webbee.auth.dto.ChangeUserRolesRequest;
import com.webbee.auth.dto.RoleStatusDto;
import com.webbee.auth.service.UserRoleService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserRoleController.class)
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
class UserRoleControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private UserRoleService userRoleService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("PUT /user-roles/save - успешное изменение ролей пользователя")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void save_ValidRequest_ReturnsSuccess() throws Exception {

        ChangeUserRolesRequest request = ChangeUserRolesRequest.builder()
                .username("testuser")
                .roles(Set.of("USER", "MODERATOR"))
                .build();
        RoleStatusDto response = RoleStatusDto.builder()
                .code(HttpStatus.OK.value())
                .build();
        when(userRoleService.saveRoles(any(ChangeUserRolesRequest.class))).thenReturn(response);
        mockMvc.perform(put("/user-roles/save")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value(200));
        verify(userRoleService).saveRoles(any(ChangeUserRolesRequest.class));

    }

    @Test
    @DisplayName("PUT /user-roles/save - пользователь не найден")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void save_UserNotFound_ReturnsBadRequest() throws Exception {

        ChangeUserRolesRequest request = ChangeUserRolesRequest.builder()
                .username("no")
                .roles(Set.of("USER"))
                .build();
        RoleStatusDto response = RoleStatusDto.builder()
                .code(HttpStatus.BAD_REQUEST.value())
                .build();
        when(userRoleService.saveRoles(any(ChangeUserRolesRequest.class))).thenReturn(response);
        mockMvc.perform(put("/user-roles/save")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value(400));
        verify(userRoleService).saveRoles(any(ChangeUserRolesRequest.class));

    }

    @Test
    @DisplayName("PUT /user-roles/save - роль не существует")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void save_RoleNotExists_ReturnsInternalServerError() throws Exception {

        ChangeUserRolesRequest request = ChangeUserRolesRequest.builder()
                .username("testuser")
                .roles(Set.of("NONEXISTENT_ROLE"))
                .build();
        RoleStatusDto response = RoleStatusDto.builder()
                .code(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .build();
        when(userRoleService.saveRoles(any(ChangeUserRolesRequest.class))).thenReturn(response);
        mockMvc.perform(put("/user-roles/save")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value(500));
        verify(userRoleService).saveRoles(any(ChangeUserRolesRequest.class));

    }

    @Test
    @DisplayName("PUT /user-roles/save - неавторизованный пользователь")
    void save_Unauthorized_ReturnsForbidden() throws Exception {

        ChangeUserRolesRequest request = ChangeUserRolesRequest.builder()
                .username("testuser")
                .roles(Set.of("USER"))
                .build();
        mockMvc.perform(put("/user-roles/save")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
        verifyNoInteractions(userRoleService);

    }

    @Test
    @DisplayName("GET /user-roles/{login} - администратор получает роли пользователя")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void getUserRoles_AdminUser_ReturnsUserRoles() throws Exception {

        when(userRoleService.getRoles("admin")).thenReturn(List.of("ADMIN"));
        when(userRoleService.getRoles("testuser")).thenReturn(List.of("USER", "MODERATOR"));
        mockMvc.perform(get("/user-roles/testuser"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0]").value("USER"))
                .andExpect(jsonPath("$[1]").value("MODERATOR"));
        verify(userRoleService).getRoles("admin");
        verify(userRoleService).getRoles("testuser");

    }

    @Test
    @DisplayName("GET /user-roles/{login} - пользователь получает свои роли")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void getUserRoles_OwnRoles_ReturnsUserRoles() throws Exception {

        when(userRoleService.getRoles("testuser")).thenReturn(List.of("USER"));
        mockMvc.perform(get("/user-roles/testuser"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0]").value("USER"));
        verify(userRoleService, times(2)).getRoles("testuser");

    }

    @Test
    @DisplayName("GET /user-roles/{login} - неавторизованный пользователь")
    void getUserRoles_Unauthorized_ReturnsForbidden() throws Exception {

        mockMvc.perform(get("/user-roles/testuser"))
                .andExpect(status().isForbidden());
        verifyNoInteractions(userRoleService);

    }

}