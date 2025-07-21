package com.webbee.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO для запроса регистрации нового пользователя.
 * Содержит необходимые данные для создания нового пользователя в системе.
 */

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RegistrationDto {

    private String username;
    private String password;
    private String email;

}
