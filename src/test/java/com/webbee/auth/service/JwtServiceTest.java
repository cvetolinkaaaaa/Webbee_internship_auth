package com.webbee.auth.service;

import com.webbee.auth.entity.Role;
import com.webbee.auth.entity.User;
import com.webbee.auth.security.model.CustomUserDetails;
import com.webbee.auth.security.model.TokenData;
import com.webbee.auth.security.service.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JwtServiceTest {

    @InjectMocks
    private JwtService jwtService;

    @Mock
    private User mockUser;

    @Mock
    private Role mockUserRole;

    @Mock
    private Role mockAdminRole;

    @Mock
    private CustomUserDetails mockUserDetails;

    private final String testSecretKey = "test-secret-key-for-jwt-signing-minimum-32-characters";
    private final Long testLifeTime = 3600000L;

    @BeforeEach
    void setUp() {

        ReflectionTestUtils.setField(jwtService, "secretKey", testSecretKey);
        ReflectionTestUtils.setField(jwtService, "lifeTime", testLifeTime);
        when(mockUserRole.getName()).thenReturn("USER");
        when(mockAdminRole.getName()).thenReturn("ADMIN");
        when(mockUser.getId()).thenReturn(1L);
        when(mockUser.getUsername()).thenReturn("testuser");
        when(mockUser.getEmail()).thenReturn("test@example.com");
        when(mockUser.getRoles()).thenReturn(Set.of(mockUserRole, mockAdminRole));
        List<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN")
        );
        when(mockUserDetails.getId()).thenReturn(1L);
        when(mockUserDetails.getUsername()).thenReturn("testuser");
        when(mockUserDetails.getEmail()).thenReturn("test@example.com");
        doReturn(authorities).when(mockUserDetails).getAuthorities();

    }

    @Test
    @DisplayName("Генерация JWT токена из CustomUserDetails")
    void generateJwtToken_WithCustomUserDetails_ReturnsValidToken() {

        String token = jwtService.generateJwtToken(mockUserDetails, 1L);
        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();
        assertThat(token.split("\\.")).hasSize(3);
        TokenData tokenData = jwtService.parseToken(token);
        assertThat(tokenData.getUsername()).isEqualTo("testuser");
        assertThat(tokenData.getId()).isEqualTo(1L);
        assertThat(tokenData.getAuthorities()).hasSize(2);

    }

    @Test
    @DisplayName("Генерация JWT токена из User")
    void generateJwtToken_WithUser_ReturnsValidToken() {

        String token = jwtService.generateJwtToken(mockUser);
        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();
        assertThat(token.split("\\.")).hasSize(3);
        TokenData tokenData = jwtService.parseToken(token);
        assertThat(tokenData.getUsername()).isEqualTo("testuser");
        assertThat(tokenData.getId()).isEqualTo(1L);
        assertThat(tokenData.getAuthorities()).hasSize(2);

    }

    @Test
    @DisplayName("Парсинг валидного JWT токена")
    void parseToken_ValidToken_ReturnsTokenData() {

        String token = jwtService.generateJwtToken(mockUser);
        TokenData tokenData = jwtService.parseToken(token);
        assertThat(tokenData.getToken()).isEqualTo(token);
        assertThat(tokenData.getUsername()).isEqualTo("testuser");
        assertThat(tokenData.getId()).isEqualTo(1L);
        assertThat(tokenData.getAuthorities()).hasSize(2);
        assertThat(tokenData.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");

    }

    @Test
    @DisplayName("Парсинг null токена")
    void parseToken_NullToken_ThrowsException() {

        assertThatThrownBy(() -> jwtService.parseToken(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Token cannot be null or empty");

    }

    @Test
    @DisplayName("Парсинг пустого токена")
    void parseToken_EmptyToken_ThrowsException() {

        assertThatThrownBy(() -> jwtService.parseToken(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Token cannot be null or empty");

    }

    @Test
    @DisplayName("Парсинг токена с пробелами")
    void parseToken_BlankToken_ThrowsException() {

        assertThatThrownBy(() -> jwtService.parseToken("   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Token cannot be null or empty");

    }

    @Test
    @DisplayName("Парсинг невалидного токена")
    void parseToken_InvalidToken_ThrowsException() {

        assertThatThrownBy(() -> jwtService.parseToken("invalid.token.format"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid JWT token");

    }

    @Test
    @DisplayName("Проверка истечения срока действия валидного токена")
    void isTokenExpired_ValidToken_ReturnsFalse() {

        String token = jwtService.generateJwtToken(mockUser);
        boolean isExpired = jwtService.isTokenExpired(token);
        assertThat(isExpired).isFalse();

    }

    @Test
    @DisplayName("Проверка истечения срока действия истекшего токена")
    void isTokenExpired_ExpiredToken_ReturnsTrue() throws Exception {

        JwtService shortLifeService = new JwtService();
        ReflectionTestUtils.setField(shortLifeService, "secretKey", testSecretKey);
        ReflectionTestUtils.setField(shortLifeService, "lifeTime", 1L);
        String token = shortLifeService.generateJwtToken(mockUser);
        Thread.sleep(2);
        boolean isExpired = shortLifeService.isTokenExpired(token);
        assertThat(isExpired).isTrue();

    }

    @Test
    @DisplayName("Проверка истечения срока действия невалидного токена")
    void isTokenExpired_InvalidToken_ThrowsException() {

        assertThatThrownBy(() -> jwtService.isTokenExpired("invalid.token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid JWT token");

    }

    @Test
    @DisplayName("Получение ID пользователя из токена")
    void getUserIdFromToken_ValidToken_ReturnsUserId() {

        String token = jwtService.generateJwtToken(mockUser);
        Long userId = jwtService.getUserIdFromToken(token);
        assertThat(userId).isEqualTo(1L);

    }

    @Test
    @DisplayName("Получение ID пользователя из невалидного токена")
    void getUserIdFromToken_InvalidToken_ThrowsException() {

        assertThatThrownBy(() -> jwtService.getUserIdFromToken("invalid.token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid JWT token");

    }

    @Test
    @DisplayName("Получение имени пользователя из токена")
    void getUserNameFromToken_ValidToken_ReturnsUsername() {

        String token = jwtService.generateJwtToken(mockUser);
        String username = jwtService.getUserNameFromToken(token);
        assertThat(username).isEqualTo("testuser");

    }

    @Test
    @DisplayName("Получение имени пользователя из невалидного токена")
    void getUserNameFromToken_InvalidToken_ThrowsException() {

        assertThatThrownBy(() -> jwtService.getUserNameFromToken("invalid.token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid JWT token");

    }

    @Test
    @DisplayName("Получение ролей из токена")
    void getRolesFromToken_ValidToken_ReturnsRoles() {

        String token = jwtService.generateJwtToken(mockUser);
        List<String> roles = jwtService.getRolesFromToken(token);
        assertThat(roles).hasSize(2);
        assertThat(roles).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");

    }

    @Test
    @DisplayName("Получение ролей из невалидного токена")
    void getRolesFromToken_InvalidToken_ThrowsException() {

        assertThatThrownBy(() -> jwtService.getRolesFromToken("invalid.token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid JWT token");

    }

    @Test
    @DisplayName("Генерация токена для пользователя без ролей")
    void generateJwtToken_UserWithoutRoles_GeneratesTokenWithEmptyRoles() {

        when(mockUser.getRoles()).thenReturn(Set.of());
        String token = jwtService.generateJwtToken(mockUser);
        List<String> roles = jwtService.getRolesFromToken(token);
        assertThat(roles).isEmpty();

    }

    @Test
    @DisplayName("Токены с одинаковыми данными должны иметь разное время создания")
    void generateJwtToken_SameUserTwice_TokensHaveDifferentIssuedAt() throws Exception {

        String token1 = jwtService.generateJwtToken(mockUser);
        Thread.sleep(1000);
        String token2 = jwtService.generateJwtToken(mockUser);
        assertThat(token1).isNotEqualTo(token2);
        TokenData tokenData1 = jwtService.parseToken(token1);
        TokenData tokenData2 = jwtService.parseToken(token2);
        assertThat(tokenData1.getUsername()).isEqualTo(tokenData2.getUsername());
        assertThat(tokenData1.getId()).isEqualTo(tokenData2.getId());

    }

    @Test
    @DisplayName("Проверка корректности работы с истекшим токеном в ExpiredJwtException")
    void isTokenExpired_ExpiredJwtException_ReturnsTrue() {

        JwtService expiredService = new JwtService();
        ReflectionTestUtils.setField(expiredService, "secretKey", testSecretKey);
        ReflectionTestUtils.setField(expiredService, "lifeTime", -1000L);
        String expiredToken = expiredService.generateJwtToken(mockUser);
        boolean isExpired = jwtService.isTokenExpired(expiredToken);
        assertThat(isExpired).isTrue();

    }

    @Test
    @DisplayName("Проверка содержимого claims в сгенерированном токене")
    void generateJwtToken_CheckClaimsContent_ContainsExpectedData() {

        String token = jwtService.generateJwtToken(mockUser);
        Long userId = jwtService.getUserIdFromToken(token);
        String username = jwtService.getUserNameFromToken(token);
        List<String> roles = jwtService.getRolesFromToken(token);
        assertThat(userId).isEqualTo(1L);
        assertThat(username).isEqualTo("testuser");
        assertThat(roles).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");

    }

    @Test
    @DisplayName("Генерация токена с пользователем с null именем")
    void generateJwtToken_UserWithNullUsername_GeneratesToken() {

        when(mockUser.getUsername()).thenReturn(null);
        String token = jwtService.generateJwtToken(mockUser);
        assertThat(token).isNotNull();
        assertThat(jwtService.getUserNameFromToken(token)).isNull();

    }

    @Test
    @DisplayName("Генерация токена с CustomUserDetails с пустыми ролями")
    void generateJwtToken_CustomUserDetailsWithEmptyRoles_GeneratesToken() {

        when(mockUserDetails.getAuthorities()).thenReturn(List.of());
        String token = jwtService.generateJwtToken(mockUserDetails, 1L);
        List<String> roles = jwtService.getRolesFromToken(token);
        assertThat(roles).isEmpty();

    }


    @Test
    @DisplayName("Обработка ExpiredJwtException при парсинге токена")
    void parseToken_ExpiredToken_ThrowsExpiredJwtException() {

        JwtService expiredService = new JwtService();
        ReflectionTestUtils.setField(expiredService, "secretKey", testSecretKey);
        ReflectionTestUtils.setField(expiredService, "lifeTime", -1000L);
        String expiredToken = expiredService.generateJwtToken(mockUser);
        assertThatThrownBy(() -> jwtService.parseToken(expiredToken))
                .isInstanceOf(ExpiredJwtException.class);

    }

}
