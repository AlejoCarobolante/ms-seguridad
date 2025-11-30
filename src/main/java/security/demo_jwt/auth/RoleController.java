package security.demo_jwt.auth;


import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import security.demo_jwt.Domain.Role;

import java.util.List;

@RestController
@RequestMapping(value = "admin/roles")
@RequiredArgsConstructor
public class RoleController {

    private final AuthService authService;

    @PostMapping(value = "create")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Role> createRole(@Valid @RequestBody RoleRequest request, @RequestHeader(HttpHeaders.AUTHORIZATION) String token){
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(authService.createRole(request, token));
    }

    @GetMapping(value = "get")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Role>> listRoles(@RequestHeader(HttpHeaders.AUTHORIZATION) String token){
        return ResponseEntity.ok(authService.getAllRoles(token));
    }

    @PutMapping(value = "update/{roleId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Role> updateRole(@PathVariable Integer roleId, @Valid @RequestBody RoleRequest request, @RequestHeader(HttpHeaders.AUTHORIZATION) String token){
        return ResponseEntity.ok(authService.updateRole(roleId, request, token));
    }

    @DeleteMapping(value = "delete/{roleId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteRole(@PathVariable Integer roleId, @RequestHeader(HttpHeaders.AUTHORIZATION) String token){
        authService.deleteRole(roleId, token);
        return ResponseEntity.noContent().build();
    }
}
