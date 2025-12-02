package security.demo_jwt.modules.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;
import security.demo_jwt.core.security.services.AuditService;
import security.demo_jwt.core.email.UserVerificationEmailService;
import security.demo_jwt.core.security.jwt.JwtService;
import security.demo_jwt.domain.model.*;
import security.demo_jwt.domain.repository.ClientAppRepository;
import security.demo_jwt.domain.repository.RoleRepository;
import security.demo_jwt.domain.repository.TokenRepository;
import security.demo_jwt.domain.repository.UserRepository;
import security.demo_jwt.modules.auth.dto.AuthResponse;
import security.demo_jwt.modules.auth.dto.LoginRequest;
import security.demo_jwt.modules.auth.dto.RegisterRequest;
import security.demo_jwt.core.email.PasswordRecoverEmailService;
import security.demo_jwt.core.security.services.LoginAttemptService;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;


@Service
@RequiredArgsConstructor
public class AuthService {


    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserVerificationEmailService userVerificationEmailService;
    private final TokenRepository tokenRepository;
    private final ClientAppRepository clientAppRepository;
    private final AuditService auditService;
    private final PasswordRecoverEmailService passwordRecoverEmailService;
    private final LoginAttemptService loginAttemptService;



    public AuthResponse register(RegisterRequest registerRequest, HttpServletRequest request, String apiKey) {

        ClientApp app = clientAppRepository.findByApiKey(apiKey)
                .orElseThrow(()-> new RuntimeException("API KEY Invalida."));
        if (userRepository.findByEmailAndClientApp(registerRequest.getEmail(), app).isPresent()) {
            throw new RuntimeException("El usuario ya existe en esta organizacion.");
        }

        String generatedCode = java.util.UUID.randomUUID().toString();

        Role initialRole = roleRepository.findByName("PENDING_VALIDATION")
                .orElseThrow(() -> new RuntimeException("Error: Rol PENDING_VALIDATION no encontrado"));

        User user = User.builder()
                .username(registerRequest.getUsername())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .dateOfBirth(registerRequest.getDateOfBirth())
                .email(registerRequest.getEmail())
                .verificationCode(generatedCode)
                .roles(new ArrayList<>(List.of(initialRole)))
                .clientApp(app)
                .build();

        var savedUser = userRepository.save(user);

        auditService.log(
                AuditAction.REGISTER_SUCCESS,
                user.getEmail(),
                "Usuario registrado con rol default",
                app.getName(),
                request
        );

        userVerificationEmailService.sendVerificationEmail(user.getEmail(), user.getUsername(), user.getVerificationCode(), app.getName());

        var jwtToken = jwtService.getToken(user);

        saveUserToken(savedUser, jwtToken, request);

        return AuthResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    public AuthResponse login(LoginRequest loginRequest, HttpServletRequest request, String apiKey) {

        if(loginAttemptService.isBlocked(loginRequest.getEmail())){
            throw new RuntimeException("Cuenta temporalmente bloqueada.");
        }

        ClientApp app = clientAppRepository.findByApiKey(apiKey)
                        .orElseThrow(()->new RuntimeException("API KEY Invalida"));

        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail() + ":" + apiKey, loginRequest.getPassword())
            );

            loginAttemptService.loginSucceded(loginRequest.getEmail());
        } catch (BadCredentialsException e){
            loginAttemptService.loginFailed(loginRequest.getEmail());
            throw e;
        }



        var user = userRepository.findByEmailAndClientApp(loginRequest.getEmail(), app).orElseThrow();

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail() + ":" + apiKey,
                            loginRequest.getPassword()
                    )
            );
        } catch (BadCredentialsException e) {

            auditService.log(
                    AuditAction.LOGIN_FAILED,
                    loginRequest.getEmail(),
                    "Credenciales incorrectas",
                    app.getName(),
                    request
            );
            throw e;
        }

        var jwtToken = jwtService.getToken(user);

        revokeAllUserTokens(user);

        saveUserToken(user, jwtToken, request);

        return AuthResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    public void logout(String authHeader){

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }

        String jwt = authHeader.substring(7);

        var storedToken = tokenRepository.findByToken(jwt)
                .orElse(null);

        if(storedToken != null && !storedToken.isExpired() && !storedToken.isRevoked()){
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
        }
    }

    public String verifyUser(String code){
        User user = userRepository.findByVerificationCode(code)
                .orElseThrow(() -> new RuntimeException("Codigo o Usuario Invalido"));
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Rol USER no configurado"));
        List<Role> newRole = new ArrayList<>();
        newRole.add(userRole);
        user.setRoles(newRole);
        user.setVerificationCode(null);

        userRepository.save(user);

        return "Cuenta verificada con exito";
    }

    public void forgotPassword(String email, String apiKey){
        ClientApp app = clientAppRepository.findByApiKey(apiKey)
                .orElseThrow(() -> new RuntimeException("API KEY Invalida"));
        User user = userRepository.findByEmailAndClientApp(email, app)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        String token = UUID.randomUUID().toString();

        user.setResetPasswordToken(token);
        user.setResetPasswordTokenExpiry(LocalDateTime.now().plusMinutes(10));

        userRepository.save(user);

        passwordRecoverEmailService.sendResetEmail(user.getEmail(), user.getUsername(), token);
    }

    public void resetPassword(String token, String newPassword){
        User user = userRepository.findByResetPasswordToken(token)
                .orElseThrow(() -> new RuntimeException("Token invalido."));

        if(user.getResetPasswordTokenExpiry().isBefore(java.time.LocalDateTime.now())){
            throw new RuntimeException("El token ha expirado.");
        }

        user.setPassword(passwordEncoder.encode(newPassword));

        user.setResetPasswordToken(null);
        user.setResetPasswordTokenExpiry(null);

        userRepository.save(user);
    }

    private void saveUserToken(User user, String jwtToken, HttpServletRequest request){

        String userAgent = request.getHeader("User-Agent");
        if(userAgent == null) userAgent = "Unknown";

        String ip = request.getRemoteAddr();

        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .expired(false)
                .revoked(false)
                .ipAdress(ip)
                .deviceInfo(userAgent)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;

        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public AuthResponse refreshToken(HttpServletRequest request){
        final String authHeader = request.getHeader("Authorization");
        final String refreshToken;
        final String userIdString;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Refresh Token no encontrado");
        }

        refreshToken = authHeader.substring(7);
        userIdString = jwtService.getUserIdFromToken(refreshToken);

        if(userIdString != null){

            Integer userId = Integer.parseInt(userIdString);

            var user = this.userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("Usuario no encontrado para este token"));

            if (jwtService.isTokenValid(refreshToken, user)){
                var accessToken = jwtService.getToken(user);
                var newRefreshToken = jwtService.getRefreshToken(user);

                revokeAllUserTokens(user);
                saveUserToken(user, accessToken, request);
                saveUserToken(user, newRefreshToken, request);

                return AuthResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(newRefreshToken)
                        .build();
            }
        }
        throw new RuntimeException("Token invalido");
    }

}
