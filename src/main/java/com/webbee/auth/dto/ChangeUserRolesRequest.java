package com.webbee.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

/**
 * DTO для запроса изменения ролей пользователя.
 * Используется администраторами для управления ролями пользователей.
 */

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ChangeUserRolesRequest {

    private String username;
    private Set<String> roles;

}
