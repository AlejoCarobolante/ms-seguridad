package security.demo_jwt.modules.user;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
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
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<SessionResponse>> getAllUserSessions(
            @PathVariable Integer userId
    ){
        return ResponseEntity.ok(userService.getSessionByUserId(userId));
    }

    @GetMapping(value = "admin/getallusers")
    public ResponseEntity<List<UserResponse>> getAllUsers(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ){
        return ResponseEntity.ok(userService.getAllUsersByMyOrg(token));
    }

    @GetMapping(value = "me")
    public ResponseEntity<UserProfileResponse> getMyProfile(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ) {
        return ResponseEntity.ok(userService.getMyProfile(token));
    }

    @PutMapping(value = "me")
    public ResponseEntity<UserProfileResponse> updateProfile(
            @Valid @RequestBody UpdateProfileRequest request,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ) {
        return ResponseEntity.ok(userService.updateMyProfile(request, token));
    }

    @PutMapping(value = "me/password")
    public ResponseEntity<String> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token
    ) {
        userService.changePassword(request, token);
        return ResponseEntity.ok("Contraseña actualizada correctamente.");
    }

}
