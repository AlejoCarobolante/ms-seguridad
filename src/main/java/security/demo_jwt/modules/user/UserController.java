package security.demo_jwt.modules.user;

import io.swagger.v3.oas.annotations.Parameter;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import security.demo_jwt.domain.model.User;
import security.demo_jwt.modules.user.dto.*;

import java.util.List;

@RestController
@RequestMapping(value = "users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping(value = "sessions")
    public ResponseEntity<List<SessionResponse>> getMySessions(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ){
        return ResponseEntity.ok(userService.getUserSessions(token));
    }

    @DeleteMapping(value = "sessions/{id}")
    public ResponseEntity<String> closeSession(
            @PathVariable Integer id,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ){
        userService.closeSession(id, token);
        return ResponseEntity.ok("Sesion cerrada exitosamente");
    }

    @GetMapping(value = "admin/users/{userId}/sessions")
    @PreAuthorize("hasRole('SUPER_ADMIN', 'ROLE_SUPER_ADMIN', 'TENANT_ADMIN')")
    public ResponseEntity<List<SessionResponse>> getAllUserSessions(
            @PathVariable Integer userId
    ){
        return ResponseEntity.ok(userService.getSessionByUserId(userId));
    }

    @GetMapping(value = "admin/users")
    @PreAuthorize("hasRole('SUPER_ADMIN', 'ROLE_SUPER_ADMIN', 'TENANT_ADMIN')")
    public ResponseEntity<Page<UserResponse>> getAllUsers(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token,
            @PageableDefault(size = 10, sort = "credential")Pageable pageable
            ){
        return ResponseEntity.ok(userService.getAllUsersByMyOrg(token, pageable));
    }

    @GetMapping(value = "me")
    public ResponseEntity<UserProfileResponse> getMyProfile(
            Authentication authentication
    ) {
        User user = (User) authentication.getPrincipal();
        return ResponseEntity.ok(userService.getMyProfile(user));
    }

    @PutMapping(value = "me")
    public ResponseEntity<UserProfileResponse> updateProfile(
            @Valid @RequestBody UpdateProfileRequest request,
            Authentication authentication
    ) {
        User user = (User) authentication.getPrincipal();
        return ResponseEntity.ok(userService.updateMyProfile(request, user));
    }

    @PutMapping(value = "me/password")
    public ResponseEntity<String> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ) {
        userService.changePassword(request, token);
        return ResponseEntity.ok("Contraseña actualizada correctamente.");
    }

    //REVISAR
    @PutMapping(value = "admin/users/{userId}/role/{roleId}")
    @PreAuthorize("hasRole('SUPER_ADMIN', 'ROLE_SUPER_ADMIN', 'TENANT_ADMIN')")
    public ResponseEntity<String> changeUserRole(
            @PathVariable Integer userId,
            @PathVariable Integer roleId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ) {
        userService.addRoleToUser(userId, roleId, token);
        return ResponseEntity.ok("Rol del usuario actualizado correctamente.");
    }

    @PostMapping(value = "admin/users/{userId}/roles/{roleId}")
    @PreAuthorize("hasRole('SUPER_ADMIN', 'ROLE_SUPER_ADMIN', 'TENANT_ADMIN')")
    public ResponseEntity<String> addRoleToUser(
            @PathVariable Integer userId,
            @PathVariable Integer roleId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ) {
        userService.addRoleToUser(userId, roleId, token);
        return ResponseEntity.ok("Rol agregado al usuario correctamente.");
    }

    @DeleteMapping(value = "admin/users/{userId}/roles/{roleId}")
    @PreAuthorize("hasRole('SUPER_ADMIN', 'ROLE_SUPER_ADMIN', 'TENANT_ADMIN')")
    public ResponseEntity<String> removeRoleFromUser(
            @PathVariable Integer userId,
            @PathVariable Integer roleId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ) {
        userService.removeRoleFromUser(userId, roleId, token);
        return ResponseEntity.ok("Rol eliminado del usuario correctamente.");
    }

    @PutMapping(value = "admin/users/{userId}/roles")
    @PreAuthorize("hasRole('SUPER_ADMIN', 'ROLE_SUPER_ADMIN', 'TENANT_ADMIN')")
    public ResponseEntity<String> updateUserRoles(
            @PathVariable Integer userId,
            @RequestBody UpdateUserRolesRequest request,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ) {
        userService.updateUserRoles(userId, request.getRoleIds(), token);
        return ResponseEntity.ok("Lista de roles actualizada correctamente.");
    }

    @PutMapping(value = "admin/users/{userId}/ban")
    @PreAuthorize("hasRole('SUPER_ADMIN', 'ROLE_SUPER_ADMIN', 'TENANT_ADMIN')")
    public ResponseEntity<String> toggleBanUser(
            @PathVariable Integer userId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ) {
        userService.toggleUserBan(userId, token);
        return ResponseEntity.ok("Estado de bloqueo del usuario actualizado.");
    }
}

