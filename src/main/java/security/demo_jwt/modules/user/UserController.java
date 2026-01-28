package security.demo_jwt.modules.user;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import security.demo_jwt.modules.user.dto.*;
import security.demo_jwt.modules.user.UserService;


@RestController
@RequestMapping("users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("admin")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','TENANT_ADMIN','SUPPORT')")
    public ResponseEntity<Page<UserResponse>> getUsers(
            @PageableDefault(size = 10) Pageable pageable
    ) {
        return ResponseEntity.ok(userService.getUsers(pageable));
    }

    @PostMapping("admin/{userId}/roles/{roleId}")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','TENANT_ADMIN')")
    public ResponseEntity<Void> addRole(
            @PathVariable Integer userId,
            @PathVariable Integer roleId
    ) {
        userService.addRoleToUser(userId, roleId);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("admin/{userId}/roles/{roleId}")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','TENANT_ADMIN')")
    public ResponseEntity<Void> removeRole(
            @PathVariable Integer userId,
            @PathVariable Integer roleId
    ) {
        userService.removeRoleFromUser(userId, roleId);
        return ResponseEntity.ok().build();
    }
}


