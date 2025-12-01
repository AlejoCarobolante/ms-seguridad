package security.demo_jwt.modules.user;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import security.demo_jwt.core.security.jwt.JwtService;
import security.demo_jwt.domain.model.*;
import security.demo_jwt.domain.repository.TokenRepository;
import security.demo_jwt.domain.repository.UserRepository;
import security.demo_jwt.modules.user.dto.SessionResponse;
import security.demo_jwt.modules.user.dto.UserResponse;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;

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

    public List<UserResponse> getAllUsersByMyOrg(String token){
        String cleanToken = token.startsWith("Bearer ")?token.substring(7):token;
        String adminIdString = jwtService.getUserIdFromToken(cleanToken);
        Integer adminId = Integer.parseInt(adminIdString);

        User admin = userRepository.findById(adminId)
                .orElseThrow(()-> new RuntimeException("Administrador de la organizacion no encotnrado"));

        List<User> users = userRepository.findAllByClientApp(admin.getClientApp());

        return users.stream()
                .map(u -> UserResponse.builder()
                        .id(u.getId())
                        .username(u.getUsername())
                        .email(u.getEmail())
                        .firstName(u.getFirstName())
                        .lastName(u.getLastName())
                        .isEnabled(u.isEnabled())
                        .isLocked(u.isAccountNonLocked())
                        .roles(u.getRoles().stream()
                                .map(role -> role.getName())
                                .collect(Collectors.toList()))
                        .build()
                )
                .collect(Collectors.toList());
    }
}
