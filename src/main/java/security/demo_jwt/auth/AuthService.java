package security.demo_jwt.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import security.demo_jwt.Domain.Role;
import security.demo_jwt.Domain.User;
import security.demo_jwt.Domain.UserRepository;
import security.demo_jwt.Domain.RoleRepository;
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

    public AuthResponse login(LoginRequest request) {

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        UserDetails user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        String token = jwtService.getToken(user);
        return AuthResponse.builder()
                .token(token)
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

        userRepository.save(user);

        userVerificationEmailService.sendVerificationEmail(user.getEmail(), user.getUsername(), user.getVerificationCode());
        

        return AuthResponse.builder()
        .token(jwtService.getToken(user))
        .build();
    }

    public String verifyUser(String code){ //Metodo para validar a partir del mail recibido
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
}
