package security.demo_jwt.modules.user;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import security.demo_jwt.core.security.jwt.JwtService;
import security.demo_jwt.core.security.services.UserContextService;
import security.demo_jwt.domain.model.*;
import security.demo_jwt.domain.repository.PasswordHistoryRepository;
import security.demo_jwt.domain.repository.RoleRepository;
import security.demo_jwt.domain.repository.TokenRepository;
import security.demo_jwt.domain.repository.UserRepository;
import security.demo_jwt.modules.auth.AuthService;
import security.demo_jwt.modules.user.dto.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final UserContextService userContextService;
    private final PasswordEncoder passwordEncoder;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final RoleRepository roleRepository;
    private final AuthService authService;

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

    public Page<UserResponse> getAllUsersByMyOrg(String token, Pageable pageable){
        String cleanToken = token.startsWith("Bearer ")?token.substring(7):token;
        String adminIdString = jwtService.getUserIdFromToken(cleanToken);
        Integer adminId = Integer.parseInt(adminIdString);

        User admin = userRepository.findById(adminId)
                .orElseThrow(()-> new RuntimeException("Administrador de la organizacion no encotnrado"));

        Page<User> userPage = userRepository.findAllByClientApp(admin.getClientApp(), pageable);

        return userPage.map(u -> UserResponse.builder()
                .id(u.getId())
                .username(u.getUsername())
                .email(u.getEmail())
                .firstName(u.getFirstName())
                .lastName(u.getLastName())
                .isEnabled(u.isEnabled())
                .isLocked(!u.isAccountNonLocked())
                .roles(u.getRoles().stream().map(Role::getName).toList())
                .build()
        );
    }

    public UserProfileResponse getMyProfile(String token){

        User user = userContextService.getCurrentUserFromToken(token);

        return UserProfileResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .dateOfBirth(user.getDateOfBirth())
                .organizationName(user.getClientApp().getName())
                .roles(user.getRoles().stream().map(Role::getName).toList())
                .build();
    }

    public UserProfileResponse updateMyProfile(UpdateProfileRequest request, String token){

        User user = userContextService.getCurrentUserFromToken(token);

        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setDateOfBirth(request.getDateOfBirth());

        userRepository.save(user);

        return getMyProfile(token);
    }

    private void checkPasswordHistory(User user, String newPassword){
        List<PasswordHistory> history = passwordHistoryRepository.findLastPasswords(user.getId());

        //REvisar anteriores
        int limit = 3;
        for(int i = 0; i< Math.min(history.size(),limit); i++){
            String oldHash = history.get(i).getPassword();
            if(passwordEncoder.matches(newPassword, oldHash)){
                throw new RuntimeException("La contraseña no puede ser igual a una de las ultimas " + limit);
            }
        }
    }

    private void saveToHistory(User user){
        PasswordHistory entry = PasswordHistory.builder()
                .user(user)
                .password(user.getPassword())
                .createdAt(LocalDateTime.now())
                .build();

        passwordHistoryRepository.save(entry);
    }

    public void changePassword(ChangePasswordRequest request, String token){

        User user = userContextService.getCurrentUserFromToken(token);

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())){
            throw new RuntimeException("La contraseña actual es incorrecta");
        }

        checkPasswordHistory(user, request.getNewPassword());
        saveToHistory(user);

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    public void changeUserRole(Integer userId, Integer roleId, String token){
        User admin = userContextService.getCurrentUserFromToken(token);

        User targetUser = userRepository.findById(userId)
                .orElseThrow(()-> new RuntimeException("Usuario objetivo no encontrado"));

        if (!targetUser.getClientApp().getId().equals(admin.getClientApp().getId())){
            throw new RuntimeException("Permisos insuficientes para gestionar roles de otros usuarios");
        }

        Role newRole = roleRepository.findById(roleId)
                .orElseThrow(()-> new RuntimeException("Rol no encontrado"));

        if (!newRole.getClientApp().getId().equals(admin.getClientApp().getId())){
            throw new RuntimeException("El rol no pertenece a tu organizacion");
        }

        targetUser.setRoles(new ArrayList<>(List.of(newRole)));
        userRepository.save(targetUser);
    }

    public void toggleUserBan(Integer userId, String token){
        User admin = userContextService.getCurrentUserFromToken(token);

        User targetUser = userRepository.findById(userId)
                .orElseThrow(()-> new RuntimeException("Usuario no encontrado"));

        if (!targetUser.getClientApp().getId().equals(admin.getClientApp().getId())){
            throw new RuntimeException("El usuario no pertenece a tu organizacion");
        }

        if(targetUser.getId().equals(admin.getId())){
            throw new RuntimeException("No podes bloquear tu propia cuenta");
        }

        boolean toggleBan = !targetUser.isAccountLocked();
        targetUser.setAccountLocked(toggleBan);

        userRepository.save(targetUser);

        if(toggleBan){
            authService.revokeAllUserTokens(targetUser);
        }
    }
}
