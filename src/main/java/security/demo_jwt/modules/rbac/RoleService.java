package security.demo_jwt.modules.rbac;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import security.demo_jwt.core.security.jwt.JwtService;
import security.demo_jwt.core.security.services.UserContextService;
import security.demo_jwt.domain.model.ClientApp;
import security.demo_jwt.domain.model.Permission;
import security.demo_jwt.domain.model.Role;
import security.demo_jwt.domain.model.User;
import security.demo_jwt.domain.repository.ClientAppRepository;
import security.demo_jwt.domain.repository.PermissionRepository;
import security.demo_jwt.domain.repository.RoleRepository;
import security.demo_jwt.modules.rbac.dto.PermissionAssignementRequest;
import security.demo_jwt.modules.rbac.dto.RoleRequest;

import java.util.HashSet;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;
    private final UserContextService userContextService;
    private final PermissionRepository permissionRepository;
    private final ClientAppRepository clientAppRepository;
    private final JwtService jwtService;

    public Role createRole(RoleRequest request, String token){
        User currentUser = userContextService.getCurrentUserFromToken(token);

        //REEMPLAZAR EL ID HARDCODEADO POR UN SECRET
        boolean isSudo = currentUser.getClientApp().getId() == 1 && currentUser.getRoles().stream().anyMatch(r -> r.getName().equals("ROLE_SUPER_ADMIN"));

        Role newRole = Role.builder()
                .name(request.getName())
                .creator(currentUser)
                .build();

        if (isSudo){
            if(request.getTargetCientAppId() != null){
                ClientApp target = clientAppRepository.findById(request.getTargetCientAppId()).orElseThrow(() -> new RuntimeException("Tenant no encontrado"));
                newRole.setClientApp(target);
            } else {
                newRole.setClientApp(currentUser.getClientApp());
            }
        } else {
            newRole.setClientApp(currentUser.getClientApp());
        }

        return roleRepository.save(newRole);
    }

    public List<Role> getAllRoles(String currentToken){
        User currentUser = userContextService.getCurrentUserFromToken(currentToken);

        boolean isSudo = currentUser.getRoles().stream()
                .anyMatch(r -> r.getName().equals("ROLE_SUPER_ADMIN"));

        if(isSudo){
            return roleRepository.findAll();
        }else {
            return roleRepository.findAllByClientAppId(currentUser.getClientApp().getId());
        }
    }

    public Role updateRole(Integer roleId, RoleRequest request, String currentToken){
        User currentUser = userContextService.getCurrentUserFromToken(currentToken);
        Role roleToUpdate = roleRepository.findById(roleId)
                .orElseThrow(()-> new RuntimeException("Rol no encontrado."));

        boolean isSudo = currentUser.getRoles().stream()
                .anyMatch(r -> r.getName().equals("ROLE_SUPER_ADMIN"));
        if (!isSudo) {
            if (!roleToUpdate.getClientApp().getId().equals(currentUser.getClientApp().getId())) {

                throw new RuntimeException("Acceso denegado: El rol pertenece a otra organización (Tenant).");
            }
        }
        roleToUpdate.setName(request.getName());

        return roleRepository.save(roleToUpdate);
    }

    public void deleteRole(Integer roleId, String currentToken) {
        User currentUser = userContextService.getCurrentUserFromToken(currentToken);
        Role roleToDelete = roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Rol a eliminar no encontrado."));


        if (roleToDelete.getUsers() != null && !roleToDelete.getUsers().isEmpty()) {
            throw new RuntimeException("No se puede eliminar el rol: Está asignado a uno o más usuarios.");
        }

        boolean isSudo  = currentUser.getRoles().stream()
                .anyMatch(r -> r.getName().equals("ROLE_SUPER_ADMIN"));

        if (!isSudo) {
            if (!roleToDelete.getClientApp().getId().equals(currentUser.getClientApp().getId())) {

                throw new RuntimeException("Acceso denegado: El rol pertenece a otra organización (Tenant).");
            }
        }

        roleRepository.delete(roleToDelete);
    }

    public Role assignPermissions(Integer roleId, PermissionAssignementRequest request, String currentToken) {
        User currentUser = userContextService.getCurrentUserFromToken(currentToken);
        Role roleToUpdate = roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Rol no encontrado"));

        boolean isSudo = currentUser.getClientApp().getId() == 1
                && currentUser.getRoles().stream().anyMatch(r -> r.getName().equals("ROLE_SUPER_ADMIN"));

        if (!isSudo && !roleToUpdate.getClientApp().getId().equals(currentUser.getClientApp().getId())) {
            throw new AccessDeniedException("No puedes modificar roles de otra organización.");
        }

        List<Permission> permissions = permissionRepository.findByNameIn(request.getPermissions());

        if (!isSudo) {
            List<String> forbidden = permissions.stream()
                    .filter(p -> Boolean.TRUE.equals(p.getIsSysOnly()))
                    .map(Permission::getName)
                    .toList();

            if (!forbidden.isEmpty()) {
                throw new AccessDeniedException(
                        "No tienes nivel suficiente para asignar estos permisos restringidos: " + forbidden
                );
            }
        }
        roleToUpdate.setPermissions(new HashSet<>(permissions));
        return roleRepository.save(roleToUpdate);
    }
}
