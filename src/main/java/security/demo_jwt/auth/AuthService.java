package security.demo_jwt.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import security.demo_jwt.Domain.*;
import security.demo_jwt.email.PasswordRecoverEmailService;
import security.demo_jwt.email.UserVerificationEmailService;
import security.demo_jwt.jwt.JwtService;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
class AuthService {


    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserVerificationEmailService userVerificationEmailService;
    private final PasswordRecoverEmailService passwordRecoverEmailService;
    private final TokenRepository tokenRepository;

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        var jwtToken = jwtService.getToken(user);

        revokeAllUserTokens(user);

        saveUserToken(user, jwtToken);

        return AuthResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    public AuthResponse register(RegisterRequest request) {
        String generatedCode = java.util.UUID.randomUUID().toString();

        Role initialRole = roleRepository.findByName("PENDING_VALIDATION")
                .orElseThrow(() -> new RuntimeException("Error: Rol PENDING_VALIDATION no encontrado"));

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .dateOfBirth(request.getDateOfBirth())
                .email(request.getEmail())
                .verificationCode(generatedCode)
                .roles(List.of(initialRole))
                .build();

        var savedUser = userRepository.save(user);

        userVerificationEmailService.sendVerificationEmail(user.getEmail(), user.getUsername(), user.getVerificationCode());

        var jwtToken = jwtService.getToken(user);

        saveUserToken(savedUser, jwtToken);

        return AuthResponse.builder()
                .accessToken(jwtToken)
                .build();
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

    public void forgotPassword(String email){
        User user = userRepository.findByEmail(email)
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

    private void saveUserToken(User user, String jwtToken){
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .expired(false)
                .revoked(false)
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
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            throw new RuntimeException("Refresh Token no encontrado");
        }

        refreshToken = authHeader.substring(7);
        userEmail = jwtService.getEmailFromToken(refreshToken);

        if(userEmail != null){
            var user = this.userRepository.findByEmail(userEmail)
                    .orElseThrow();

            if (jwtService.isTokenValid(refreshToken, user)){
                var accessToken = jwtService.getToken(user);
                var newRefreshToken = jwtService.getRefreshToken(user);

                revokeAllUserTokens(user);

                saveUserToken(user, accessToken);
                saveUserToken(user, newRefreshToken);

                return AuthResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(newRefreshToken)
                        .build();
            }
        }
        throw new RuntimeException("Token invalido");
    }
}
