package com.webbee.auth.service;

import com.webbee.auth.dto.ChangeUserRolesRequest;
import com.webbee.auth.dto.RoleStatusDto;
import com.webbee.auth.entity.Role;
import com.webbee.auth.entity.User;
import com.webbee.auth.repository.RoleRepository;
import com.webbee.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Сервис для управления ролями пользователей в системе
 */
@Service
@RequiredArgsConstructor
public class UserRoleService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    /**
     * Назначает или изменяет роли для указанного пользователя.
     */
    @Transactional
    public RoleStatusDto saveRoles(ChangeUserRolesRequest request) {
        Optional<User> user = userRepository.findByUsername(request.getUsername());
        RoleStatusDto response;
        if (user.isPresent()) {
            Set<Role> roles = new HashSet<>();
            request.getRoles().forEach(role -> {
                Role rl = roleRepository.findByName(role)
                        .orElseThrow(() -> new IllegalArgumentException("There is no role with that name"));
                roles.add(rl);
            });
            user.get().setRoles(roles);
            Set<String> strRoles = roles.stream().map(Role::getName).collect(Collectors.toSet());
            response = RoleStatusDto.builder()
                    .code(200)
                    .username(request.getUsername())
                    .roles(strRoles)
                    .build();
        } else {
            response = RoleStatusDto.builder()
                    .code(HttpStatus.BAD_REQUEST.value())
                    .username(request.getUsername())
                    .roles(null)
                    .build();

        }
        return response;
    }

    /**
     * Получает список текущих ролей для указанного пользователя.
     */
    @Transactional()
    public List<String> getRoles(String username) {
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            return user.getRoles().stream()
                    .map(Role::getName)
                    .collect(Collectors.toList());
        } else {
            return Collections.emptyList();
        }
    }

}
