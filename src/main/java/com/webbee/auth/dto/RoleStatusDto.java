package com.webbee.auth.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

/**
 * DTO для передачи информации о ролях пользователя.
 * Используется для возврата информации о текущих ролях пользователя
 */

@Builder
@Getter
@Setter
public class RoleStatusDto {

    private Integer code;
    private String username;
    private Set<String> roles;

}
