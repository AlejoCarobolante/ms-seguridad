package security.demo_jwt.modules.user;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import security.demo_jwt.core.security.services.UserContextService;
import security.demo_jwt.domain.model.Role;
import security.demo_jwt.domain.model.User;
import security.demo_jwt.domain.repository.RoleRepository;
import security.demo_jwt.domain.repository.UserRepository;
import security.demo_jwt.modules.user.dto.UserResponse;
import org.springframework.security.access.AccessDeniedException;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserContextService userContextService;
    private final RoleRepository roleRepository;


    /* =========================
       USERS – MULTI TENANT
       ========================= */

    public Page<UserResponse> getUsers(Pageable pageable) {

        User currentUser = userContextService.getCurrentUser();

        Page<User> users;

        if (userContextService.isSuperAdmin()) {
            users = userRepository.findAll(pageable);
        } else {
            users = userRepository.findAllByClientApp(
                    currentUser.getClientApp(),
                    pageable
            );
        }

        return users.map(this::mapToResponse);
    }

    /* =========================
       ROLES MANAGEMENT
       ========================= */

    public void addRoleToUser(Integer userId, Integer roleId) {

        User admin = userContextService.getCurrentUser();
        User targetUser = getUserWithTenantValidation(userId, admin);
        Role role = getRoleWithTenantValidation(roleId, admin);

        if (targetUser.getRoles().contains(role)) {
            throw new RuntimeException("El usuario ya posee este rol");
        }

        targetUser.getRoles().add(role);
        userRepository.save(targetUser);
    }

    public void removeRoleFromUser(Integer userId, Integer roleId) {

        User admin = userContextService.getCurrentUser();
        User targetUser = getUserWithTenantValidation(userId, admin);
        Role role = getRoleWithTenantValidation(roleId, admin);

        if (!targetUser.getRoles().contains(role)) {
            throw new RuntimeException("El usuario no tiene este rol");
        }

        if (targetUser.getRoles().size() == 1) {
            throw new RuntimeException("El usuario debe tener al menos un rol");
        }

        targetUser.getRoles().remove(role);
        userRepository.save(targetUser);
    }

    /* =========================
       SECURITY RULES
       ========================= */

    private User getUserWithTenantValidation(Integer userId, User admin) {

        User target = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (!userContextService.isSuperAdmin()
                && !target.getClientApp().getId().equals(admin.getClientApp().getId())) {
            throw new AccessDeniedException("Acceso denegado por tenant");
        }

        return target;
    }

    private Role getRoleWithTenantValidation(Integer roleId, User admin) {

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Rol no encontrado"));

        if (!userContextService.isSuperAdmin()
                && !role.getClientApp().getId().equals(admin.getClientApp().getId())) {
            throw new AccessDeniedException("Rol fuera del tenant");
        }

        return role;
    }

    /* =========================
       HELPERS
       ========================= */

    private UserResponse mapToResponse(User u) {
        return UserResponse.builder()
                .id(u.getId())
                .username(u.getUsername())
                .email(u.getEmail())
                .firstName(u.getFirstName())
                .lastName(u.getLastName())
                .isEnabled(u.isEnabled())
                .isLocked(!u.isAccountNonLocked())
                .roles(u.getRoles().stream().map(Role::getName).toList())
                .build();
    }
}

