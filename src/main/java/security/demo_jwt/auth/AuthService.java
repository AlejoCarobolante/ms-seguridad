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
import java.util.stream.Collectors;


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
    private final ClientAppRepository clientAppRepository;


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

        userVerificationEmailService.sendVerificationEmail(user.getEmail(), user.getUsername(), user.getVerificationCode(), app.getName());

        var jwtToken = jwtService.getToken(user);

        saveUserToken(savedUser, jwtToken, request);

        return AuthResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    public AuthResponse login(LoginRequest loginRequest, HttpServletRequest request, String apiKey) {

        ClientApp app = clientAppRepository.findByApiKey(apiKey)
                        .orElseThrow(()->new RuntimeException("API KEY Invalida"));

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail() + ":" + apiKey, loginRequest.getPassword())
        );


        var user = userRepository.findByEmailAndClientApp(loginRequest.getEmail(), app).orElseThrow();

        var jwtToken = jwtService.getToken(user);

        revokeAllUserTokens(user);

        saveUserToken(user, jwtToken, request);

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

    public List<SessionResponse> getUserSessions(String currentToken){

        String cleanToken = currentToken.startsWith("Bearer ")?currentToken.substring(7):currentToken;
        String userIdString = jwtService.getUserIdFromToken(cleanToken);

        Integer userId = Integer.parseInt(userIdString);
        User user = userRepository.findById(userId) // findById(Integer) ahora funciona
                .orElseThrow(() -> new RuntimeException("Usuario logueado no encontrado."));

        List<Token> tokens = tokenRepository.findAllValidTokenByUser(user.getId());

        return tokens.stream()
                .map(t -> SessionResponse.builder()
                        .id(t.getId())
                        .deviceInfo(t.getDeviceInfo())
                        .ipAdress(t.getIpAdress())
                        .isCurrentSession(t.getToken().equals(cleanToken))
                        .build()
                )
                .collect(Collectors.toList());
    }

    public List<SessionResponse> getSessionByUserId(Integer userId){
        User targetUser = userRepository.findById(userId)
                .orElseThrow(()-> new RuntimeException("Usuario no encontrado"));

        List<Token> tokens = tokenRepository.findAllValidTokenByUser(targetUser.getId());

        return tokens.stream()
                .map(t -> SessionResponse.builder()
                        .id(t.getId())
                        .deviceInfo(t.getDeviceInfo())
                        .ipAdress(t.getIpAdress())
                        .isCurrentSession(false)
                        .build()
                )
                .collect(Collectors.toList());
    }

    public void closeSession(Integer tokenId, String currentToken){
        String cleanToken = currentToken.startsWith("Bearer ")?currentToken.substring(7):currentToken;
        String userId = jwtService.getUserIdFromToken(cleanToken);
        Integer currentUserId = Integer.parseInt(userId);
        User currentUser = userRepository.findById(currentUserId).orElseThrow();

        Token tokenToDelete = tokenRepository.findById(tokenId)
                .orElseThrow(()-> new RuntimeException("Sesion no encontrada"));

        boolean isOwner = tokenToDelete.getUser().getId().equals(currentUser.getId());

        boolean isAdmin = currentUser.getRoles().stream()
                        .anyMatch(role -> role.getName().equals("ADMIN"));

        if(!isAdmin && !isOwner){
            throw new RuntimeException("Permisos insuficientes para cerrar sesion");
        }
        tokenRepository.delete(tokenToDelete);
    }
}
