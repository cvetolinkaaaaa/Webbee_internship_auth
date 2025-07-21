package com.webbee.auth.service;

import com.webbee.auth.dto.ChangeUserRolesRequest;
import com.webbee.auth.dto.RoleStatusDto;
import com.webbee.auth.entity.Role;
import com.webbee.auth.entity.User;
import com.webbee.auth.repository.RoleRepository;
import com.webbee.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserRoleService Unit Tests")
class UserRoleServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private UserRoleService userRoleService;

    private User testUser;
    private Role userRole;
    private Role adminRole;
    private Role moderatorRole;
    private ChangeUserRolesRequest validRequest;

    @BeforeEach
    void setUp() {
        userRole = Role.builder()
                .id(1L)
                .name("USER")
                .build();

        adminRole = Role.builder()
                .id(2L)
                .name("ADMIN")
                .build();

        moderatorRole = Role.builder()
                .id(3L)
                .name("SUPERUSER")
                .build();

        testUser = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .roles(new HashSet<>(Set.of(userRole)))
                .build();

        validRequest = ChangeUserRolesRequest.builder()
                .username("testuser")
                .roles(Set.of("USER", "ADMIN"))
                .build();
    }

    @Test
    void shouldSaveRolesSuccessfullyForExistingUser() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(roleRepository.findByName("ADMIN")).thenReturn(Optional.of(adminRole));

        RoleStatusDto result = userRoleService.saveRoles(validRequest);

        assertThat(result.getCode()).isEqualTo(200);
        assertThat(result.getUsername()).isEqualTo("testuser");
        assertThat(result.getRoles()).containsExactlyInAnyOrder("USER", "ADMIN");

        Set<Role> expectedRoles = Set.of(userRole, adminRole);
        assertThat(testUser.getRoles()).isEqualTo(expectedRoles);
    }

    @Test
    void shouldSaveSingleRoleSuccessfully() {
        ChangeUserRolesRequest singleRoleRequest = ChangeUserRolesRequest.builder()
                .username("testuser")
                .roles(Set.of("ADMIN"))
                .build();

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(roleRepository.findByName("ADMIN")).thenReturn(Optional.of(adminRole));

        RoleStatusDto result = userRoleService.saveRoles(singleRoleRequest);

        assertThat(result.getCode()).isEqualTo(200);
        assertThat(result.getUsername()).isEqualTo("testuser");
        assertThat(result.getRoles()).containsExactly("ADMIN");
        assertThat(testUser.getRoles()).containsExactly(adminRole);
    }

    @Test
    void shouldReturnErrorWhenUserNotFound() {
        when(userRepository.findByUsername("nonexistentuser")).thenReturn(Optional.empty());

        ChangeUserRolesRequest requestForNonExistentUser = ChangeUserRolesRequest.builder()
                .username("nonexistentuser")
                .roles(Set.of("USER"))
                .build();

        RoleStatusDto result = userRoleService.saveRoles(requestForNonExistentUser);

        assertThat(result.getCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(result.getUsername()).isEqualTo("nonexistentuser");
        assertThat(result.getRoles()).isNull();

        verify(roleRepository, never()).findByName(anyString());
    }

    @Test
    void shouldHandleEmptyRolesSet() {
        ChangeUserRolesRequest emptyRolesRequest = ChangeUserRolesRequest.builder()
                .username("testuser")
                .roles(Collections.emptySet())
                .build();

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        RoleStatusDto result = userRoleService.saveRoles(emptyRolesRequest);

        assertThat(result.getCode()).isEqualTo(200);
        assertThat(result.getUsername()).isEqualTo("testuser");
        assertThat(result.getRoles()).isEmpty();
        assertThat(testUser.getRoles()).isEmpty();
    }

    @Test
    void shouldReplaceExistingRolesWithNewOnes() {
        testUser.setRoles(new HashSet<>(Set.of(userRole, adminRole)));

        ChangeUserRolesRequest replaceRolesRequest = ChangeUserRolesRequest.builder()
                .username("testuser")
                .roles(Set.of("SUPERUSER"))
                .build();

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(roleRepository.findByName("SUPERUSER")).thenReturn(Optional.of(moderatorRole));

        RoleStatusDto result = userRoleService.saveRoles(replaceRolesRequest);

        assertThat(result.getCode()).isEqualTo(200);
        assertThat(result.getUsername()).isEqualTo("testuser");
        assertThat(result.getRoles()).containsExactly("SUPERUSER");
        assertThat(testUser.getRoles()).containsExactly(moderatorRole);
    }

    @Test
    void shouldReturnEmptyListWhenUserNotFound() {
        when(userRepository.findByUsername("nonexistentuser")).thenReturn(Optional.empty());

        List<String> result = userRoleService.getRoles("nonexistentuser");

        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyListWhenUserHasNoRoles() {
        testUser.setRoles(Collections.emptySet());
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        List<String> result = userRoleService.getRoles("testuser");

        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnSingleRoleWhenUserHasOneRole() {
        testUser.setRoles(Set.of(userRole));
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        List<String> result = userRoleService.getRoles("testuser");

        assertThat(result).containsExactly("USER");
    }

    @Test
    void shouldReturnAllRolesWhenUserHasMultipleRoles() {
        testUser.setRoles(Set.of(userRole, adminRole, moderatorRole));
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        List<String> result = userRoleService.getRoles("testuser");

        assertThat(result).containsExactlyInAnyOrder("USER", "ADMIN", "SUPERUSER");
    }

    @Test
    void shouldHandleEmptyUsernameGracefully() {
        when(userRepository.findByUsername("")).thenReturn(Optional.empty());

        List<String> result = userRoleService.getRoles("");

        assertThat(result).isEmpty();
    }

}