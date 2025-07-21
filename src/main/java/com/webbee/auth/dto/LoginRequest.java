package com.webbee.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO для запроса аутентификации пользователя.
 * Содержит учетные данные пользователя, необходимые для входа в систему.
 */

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {

    private String username;
    private String password;

}
