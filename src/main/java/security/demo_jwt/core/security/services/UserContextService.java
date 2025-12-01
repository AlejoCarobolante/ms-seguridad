package security.demo_jwt.core.security.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import security.demo_jwt.core.security.jwt.JwtService;
import security.demo_jwt.domain.model.User;
import security.demo_jwt.domain.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class UserContextService {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public User getCurrentUserFromToken(String token){
        final String cleanToken = token.startsWith("Bearer ")?token.substring(7):token;
        final String userIdString = jwtService.getUserIdFromToken(cleanToken);

        if(userIdString == null){
            throw new RuntimeException("Token invalido o sin usuario");
        }

        Integer userId;
        try {
            userId = Integer.parseInt(userIdString);
        } catch (NumberFormatException e){
            throw new RuntimeException("ID de usuario en el token no es un numero valido");
        }

        return userRepository.findById(userId)
                .orElseThrow(()-> new RuntimeException("Usuario no encontrado para el ID en el token"));
    }

}
