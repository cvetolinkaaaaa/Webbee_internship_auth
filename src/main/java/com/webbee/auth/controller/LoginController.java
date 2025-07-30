package com.webbee.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Контроллер для входа и OAuth2 аутентификации.
 * @author Evseeva Tsvetolina
 */
@Controller
@Tag(name = "Login Controller", description = "Обработка логина, OAuth2")
public class LoginController {

    /**
     * Отображает страницу входа в систему.
     */
    @Operation(
            summary = "Возвращает HTML форму логина",
            description = "Эта ручка отдает страницу с формой логина"
    )
    @GetMapping("/login")
    public String loginPage(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "message", required = false) String message,
            Model model) {

        if (error != null) {
            model.addAttribute("error", "Неверные учетные данные");
        }

        if (message != null) {
            model.addAttribute("message", message);
        }

        return "login";
    }

    /**
     * Обрабатывает callback после успешной авторизации.
     */
    @Operation(
            summary = "Redirect с токеном",
            description = "Обработка успешной авторизации",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешная авторизация",
                            content = @Content(schema = @Schema(implementation = String.class)))
            }
    )
    @ResponseBody
    @GetMapping("/redirect")
    public ResponseEntity<String> callback(@RequestParam String token) {
        return ResponseEntity.ok("Token: " + token);
    }

}
