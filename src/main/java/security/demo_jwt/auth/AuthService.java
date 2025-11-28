package security.demo_jwt.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import security.demo_jwt.Domain.Role;
import security.demo_jwt.Domain.User;
import security.demo_jwt.Domain.UserRepository;
import security.demo_jwt.Domain.RoleRepository;
import security.demo_jwt.jwt.JwtService;

import java.util.List;

@Service
@RequiredArgsConstructor
class AuthService {


    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthResponse login(LoginRequest request) {
        return null;
    }

    public AuthResponse register(RegisterRequest request) {

        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Error: Rol USER no encontrado"));
        User user = User.builder()
            .username(request.getUsername())
            .password(passwordEncoder.encode(request.getPassword()))
            .firstName(request.getFirstName())
            .lastName(request.getLastName())
            .dateOfBirth(request.getDateOfBirth())
            .email(request.getEmail())
                .roles(List.of(userRole))
                .build();

        userRepository.save(user);
        

        return AuthResponse.builder()
        .token(jwtService.getToken(user))
        .build();
    }

}
