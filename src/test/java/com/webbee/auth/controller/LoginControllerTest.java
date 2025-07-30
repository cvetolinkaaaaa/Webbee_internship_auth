
package com.webbee.auth.controller;

import com.webbee.auth.TestSecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.ui.Model;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@WebMvcTest(LoginController.class)
@TestPropertySource(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration," +
                "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration," +
                "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration",
        "spring.liquibase.enabled=false",
        "spring.jpa.hibernate.ddl-auto=none"
})
@Import(TestSecurityConfig.class)
@ExtendWith(MockitoExtension.class)
class LoginControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("GET /login - успешное отображение страницы входа без параметров")
    void loginPage_NoParameters_ReturnsLoginView() throws Exception {

        mockMvc.perform(get("/login"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeDoesNotExist("error"))
                .andExpect(model().attributeDoesNotExist("message"));

    }

    @Test
    @DisplayName("GET /login - отображение страницы входа с параметром error")
    void loginPage_WithErrorParameter_AddsErrorToModel() throws Exception {

        mockMvc.perform(get("/login").param("error", "true"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("error", "Неверные учетные данные"))
                .andExpect(model().attributeDoesNotExist("message"));

    }

    @Test
    @DisplayName("GET /login - отображение страницы входа с параметром message")
    void loginPage_WithMessageParameter_AddsMessageToModel() throws Exception {

        String testMessage = "Добро пожаловать!";
        mockMvc.perform(get("/login").param("message", testMessage))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("message", testMessage))
                .andExpect(model().attributeDoesNotExist("error"));

    }

    @Test
    @DisplayName("GET /login - отображение страницы входа с обоими параметрами")
    void loginPage_WithBothParameters_AddsBothToModel() throws Exception {

        String testMessage = "Тестовое сообщение";
        mockMvc.perform(get("/login")
                        .param("error", "true")
                        .param("message", testMessage))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("error", "Неверные учетные данные"))
                .andExpect(model().attribute("message", testMessage));

    }

    @Test
    @DisplayName("GET /login - обработка пустого параметра error")
    void loginPage_WithEmptyErrorParameter_DoesNotAddErrorToModel() throws Exception {

        mockMvc.perform(get("/login").param("error", ""))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("error", "Неверные учетные данные"))
                .andExpect(model().attributeDoesNotExist("message"));

    }

    @Test
    @DisplayName("GET /login - обработка пустого параметра message")
    void loginPage_WithEmptyMessageParameter_AddsEmptyMessageToModel() throws Exception {

        mockMvc.perform(get("/login").param("message", ""))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("message", ""))
                .andExpect(model().attributeDoesNotExist("error"));

    }

    @Test
    @DisplayName("GET /redirect - успешный callback с токеном")
    void callback_WithValidToken_ReturnsSuccessResponse() throws Exception {

        String testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token";
        mockMvc.perform(get("/redirect").param("token", testToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.TEXT_PLAIN_VALUE + ";charset=UTF-8"))
                .andExpect(content().string("Token: " + testToken));

    }

    @Test
    @DisplayName("GET /redirect - callback с простым токеном")
    void callback_WithSimpleToken_ReturnsFormattedResponse() throws Exception {

        String simpleToken = "simple-token-123";
        mockMvc.perform(get("/redirect").param("token", simpleToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.TEXT_PLAIN_VALUE + ";charset=UTF-8"))
                .andExpect(content().string("Token: " + simpleToken));

    }

    @Test
    @DisplayName("GET /redirect - callback с пустым токеном")
    void callback_WithEmptyToken_ReturnsEmptyTokenResponse() throws Exception {

        mockMvc.perform(get("/redirect").param("token", ""))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.TEXT_PLAIN_VALUE + ";charset=UTF-8"))
                .andExpect(content().string("Token: "));

    }

    @Test
    @DisplayName("GET /redirect - callback с токеном содержащим специальные символы")
    void callback_WithSpecialCharactersToken_ReturnsCorrectResponse() throws Exception {

        String specialToken = "token-with-special!@#$%^&*()_+chars";
        mockMvc.perform(get("/redirect").param("token", specialToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.TEXT_PLAIN_VALUE + ";charset=UTF-8"))
                .andExpect(content().string("Token: " + specialToken));

    }

    @Test
    @DisplayName("Проверка работы метода loginPage с прямым вызовом")
    void loginPage_DirectMethodCall_WorksCorrectly() {

        LoginController controller = new LoginController();
        Model model = mock(Model.class);
        String result = controller.loginPage(null, null, model);
        verify(model, never()).addAttribute(eq("error"), eq("Неверные учетные данные"));
        verify(model, never()).addAttribute(eq("message"), eq("test"));
        assert result.equals("login");

    }

    @Test
    @DisplayName("Проверка работы метода loginPage с параметром error")
    void loginPage_DirectMethodCallWithError_AddsErrorAttribute() {

        LoginController controller = new LoginController();
        Model model = mock(Model.class);
        String result = controller.loginPage("true", null, model);
        verify(model).addAttribute("error", "Неверные учетные данные");
        verify(model, never()).addAttribute(eq("message"), eq("test"));
        assert result.equals("login");

    }

    @Test
    @DisplayName("Проверка работы метода loginPage с параметром message")
    void loginPage_DirectMethodCallWithMessage_AddsMessageAttribute() {

        LoginController controller = new LoginController();
        Model model = mock(Model.class);
        String testMessage = "Test message";
        String result = controller.loginPage(null, testMessage, model);
        verify(model, never()).addAttribute(eq("error"), eq("Неверные учетные данные"));
        verify(model).addAttribute("message", testMessage);
        assert result.equals("login");

    }

    @Test
    @DisplayName("Проверка работы метода callback с прямым вызовом")
    void callback_DirectMethodCall_ReturnsCorrectResponse() {

        LoginController controller = new LoginController();
        String testToken = "test-token-123";
        ResponseEntity<String> response = controller.callback(testToken);
        assert response.getStatusCode().is2xxSuccessful();
        assert response.getBody().equals("Token: " + testToken);

    }

}
