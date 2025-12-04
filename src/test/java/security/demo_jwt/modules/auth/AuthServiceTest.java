package security.demo_jwt.modules.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import security.demo_jwt.core.email.UserVerificationEmailService;
import security.demo_jwt.core.security.jwt.JwtService;
import security.demo_jwt.core.security.services.AuditService;
import security.demo_jwt.domain.model.ClientApp;
import security.demo_jwt.domain.model.Role;
import security.demo_jwt.domain.model.User;
import security.demo_jwt.domain.repository.ClientAppRepository;
import security.demo_jwt.domain.repository.RoleRepository;
import security.demo_jwt.domain.repository.TokenRepository;
import security.demo_jwt.domain.repository.UserRepository;
import security.demo_jwt.modules.auth.dto.AuthResponse;
import security.demo_jwt.modules.auth.dto.RegisterRequest;

import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class) // Habilita Mockito
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private ClientAppRepository clientAppRepository;
    @Mock private TokenRepository tokenRepository;
    @Mock private JwtService jwtService;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private UserVerificationEmailService emailService;
    @Mock private AuditService auditService;
    @Mock private HttpServletRequest httprequest;
    // (Agrega los mocks que falten si tu AuthService tiene más dependencias)

    @InjectMocks
    private AuthService authService; // Aquí se inyectan los mocks

    @Test
    void register_ShouldReturnToken_WhenDataIsValid() {
        // 1. PREPARAR DATOS (Arrange)
        String apiKey = "TEST-KEY";
        RegisterRequest request = new RegisterRequest("testuser", "Pass123!", "Test", "User", new Date(), "test@mail.com");

        ClientApp mockApp = ClientApp.builder().id(1).name("TestApp").apiKey(apiKey).build();
        Role mockRole = Role.builder().name("PENDING_VALIDATION").build();
        User mockSavedUser = User.builder().id(1).email("test@mail.com").build();
        String expectedToken = "jwt-token-mock";

        // 2. ENTRENAR A LOS MOCKS (Simular comportamiento)
        when(clientAppRepository.findByApiKey(apiKey)).thenReturn(Optional.of(mockApp));
        when(userRepository.findByEmailAndClientApp(request.getEmail(), mockApp)).thenReturn(Optional.empty()); // No existe aún
        when(roleRepository.findByName("PENDING_VALIDATION")).thenReturn(Optional.of(mockRole));
        when(passwordEncoder.encode(request.getPassword())).thenReturn("encodedpass");
        when(userRepository.save(any(User.class))).thenReturn(mockSavedUser); // Simula guardar
        when(jwtService.getToken(any(User.class))).thenReturn(expectedToken);

        // 3. EJECUTAR (Act)
        // Pasamos null en el request HTTP porque en este test unitario no lo usamos o podemos mockearlo si es crítico
        AuthResponse response = authService.register(request, httprequest, apiKey);

        // 4. VERIFICAR (Assert)
        assertNotNull(response);
        assertEquals(expectedToken, response.getAccessToken());

        // Verificar que se llamó al repositorio para guardar
        verify(userRepository, times(1)).save(any(User.class));
        // Verificar que se envió el mail
        verify(emailService, times(1)).sendVerificationEmail(any(), any(), any(), any());
    }
}