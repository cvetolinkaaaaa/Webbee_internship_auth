package com.webbee.auth.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

/**
 * DTO для передачи статуса аутентификации.
 * Используется для возврата результата операций аутентификации,
 * содержит статус код операции и JWT токен в случае успешной аутентификации
 */

@Builder
@Getter
@Setter
public class AuthStatusDto {

    private Integer code;
    private String token;

}
