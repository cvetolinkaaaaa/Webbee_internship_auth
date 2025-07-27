package com.webbee.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Tag(name = "Login Controller", description = "Обработка логина, OAuth2")
public class LoginController {

    @Operation(
            summary = "Возвращает HTML форму логина",
            description = "Эта ручка отдает страницу с формой логина"
    )
    @GetMapping("/login")
    public String loginPage() {
        return "redirect:/login.html";
    }

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
        return ResponseEntity.ok("Success login with Google. Token: " + token);
    }

}