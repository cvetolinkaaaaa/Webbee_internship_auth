package com.webbee.auth.controller;

import com.webbee.auth.dto.ChangeUserRolesRequest;
import com.webbee.auth.dto.RoleStatusDto;
import com.webbee.auth.service.UserRoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/user-roles")
@RequiredArgsConstructor
@Tag(name = "User Role Management", description = "API для управления ролями пользователей")
public class UserRoleController {

    private final UserRoleService userRoleService;

    @PutMapping("/save")
    @Operation(
            summary = "Изменение ролей пользователя",
            description = "Позволяет администраторам назначать или изменять роли для указанного пользователя. " +
                    "Операция полностью заменяет текущие роли пользователя на новый набор ролей. " +
                    "Все указанные роли должны существовать в системе."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Роли успешно назначены",
                    content = @Content(schema = @Schema(implementation = RoleStatusDto.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Пользователь не найден",
                    content = @Content(schema = @Schema(implementation = RoleStatusDto.class))
            ),
            @ApiResponse(responseCode = "401", description = "Не авторизован"),
            @ApiResponse(responseCode = "403", description = "Недостаточно прав"),
            @ApiResponse(responseCode = "500", description = "Указанная роль не существует")
    })
    public ResponseEntity<RoleStatusDto> save(@RequestBody ChangeUserRolesRequest request) {
        RoleStatusDto response = userRoleService.saveRoles(request);
        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getCode()));
    }

    @GetMapping("/{login}")
    @Operation(
            summary = "Получение ролей пользователя",
            description = "Возвращает список ролей для указанного пользователя. " +
                    "Доступ к информации регулируется следующими правилами:\n" +
                    "- Администраторы (роль ADMIN) могут просматривать роли любого пользователя\n" +
                    "- Обычные пользователи могут просматривать только свои собственные роли\n" +
                    "- Если пользователь не найден или у него нет ролей, возвращается соответствующая ошибка"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Роли получены успешно",
                    content = @Content(array = @ArraySchema(schema = @Schema(type = "string")))
            ),
            @ApiResponse(responseCode = "401", description = "Не авторизован"),
            @ApiResponse(responseCode = "403", description = "Доступ запрещен"),
            @ApiResponse(responseCode = "404", description = "Пользователь не найден или у него нет ролей")
    })
    public ResponseEntity<List<String>> getUserRoles(@PathVariable String login,
                                                     Principal principal) {

        String authenticatedUserLogin = principal.getName();
        List<String> authenticatedUserRoles = userRoleService.getRoles(authenticatedUserLogin);

        if (authenticatedUserRoles.contains("ADMIN")) {
            List<String> userRoles = userRoleService.getRoles(login);
            if (userRoles.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User has no roles");
            }
            return new ResponseEntity<>(userRoles, HttpStatus.OK);
        } else {
            if (authenticatedUserLogin.equals(login)) {
                List<String> userRoles = userRoleService.getRoles(login);
                return new ResponseEntity<>(userRoles, HttpStatus.OK);
            } else {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
            }
        }
    }

}
