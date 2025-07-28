package com.webbee.auth.controller;

import com.webbee.auth.dto.AuthStatusDto;
import com.webbee.auth.dto.LoginRequest;
import com.webbee.auth.dto.RegistrationDto;
import com.webbee.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "API для аутентификации и регистрации пользователей")
public class AuthController {

    private final AuthService authService;

    @PutMapping("/signup")
    @Operation(
            summary = "Регистрация нового пользователя",
            description = "Создает новую учетную запись пользователя в системе. " +
                    "Проверяет уникальность имени пользователя и email, валидирует формат email, " +
                    "хеширует пароль и назначает базовую роль USER."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "400", description = "Переданная почта невалидная," +
                    " переданная почта уже занята, переданный логин уже занят",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthStatusDto.class))),
            @ApiResponse(responseCode = "200", description = "Пользователь успешно зарегистрировался",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthStatusDto.class))),
    })
    public ResponseEntity<AuthStatusDto> signUp(@RequestBody RegistrationDto request) {
        AuthStatusDto response = authService.registration(request);
        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getCode()));
    }

    @PostMapping("/signin")
    @Operation(
            summary = "Аутентификация пользователя",
            description = "Выполняет вход пользователя в систему. " +
                    "Проверяет учетные данные и в случае успеха выдает JWT токен для доступа к защищенным ресурсам. " +
                    "Токен также добавляется в заголовок Authorization ответа."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Пользователь успешно авторизовался",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthStatusDto.class))),
            @ApiResponse(responseCode = "403", description = "Не удалось авторизоваться",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthStatusDto.class)))
    })
    public ResponseEntity<AuthStatusDto> signIn(@RequestBody LoginRequest request) {
        AuthStatusDto response = authService.login(request);

        if (response.getCode() == HttpStatus.OK.value()) {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + response.getToken());
            return new ResponseEntity<>(response, headers, HttpStatus.OK);
        }

        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

}
