package security.demo_jwt.auth;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import security.demo_jwt.Domain.User;
import security.demo_jwt.Domain.UserRepository;
import security.demo_jwt.jwt.JwtService;

@Service
@RequiredArgsConstructor
class AuthService {


    private final UserRepository userRepository;
    private final JwtService jwtService;

    public AuthResponse login(LoginRequest request) {
        return null;
    }

    public AuthResponse register(RegisterRequest request) {
        
        User user = User.builder()
            .username(request.getUsername())
            .password(request.getPassword())
            .firstName(request.getFirstName())
            .lastName(request.getLastName())
            .dateOfBirth(request.getDateOfBirth())
            .email(request.getEmail())
            .build();
        userRepository.save(user);
        return AuthResponse.builder()
        .token(jwtService.getToken(user))
        .build();
    }

}
