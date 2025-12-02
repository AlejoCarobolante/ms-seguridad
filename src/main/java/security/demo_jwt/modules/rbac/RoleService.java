package security.demo_jwt.modules.rbac;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import security.demo_jwt.core.security.services.UserContextService;
import security.demo_jwt.domain.model.Permission;
import security.demo_jwt.domain.model.Role;
import security.demo_jwt.domain.model.User;
import security.demo_jwt.domain.repository.PermissionRepository;
import security.demo_jwt.domain.repository.RoleRepository;
import security.demo_jwt.modules.rbac.dto.PermissionAssignementRequest;
import security.demo_jwt.modules.rbac.dto.RoleRequest;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;
    private final UserContextService userContextService;
    private final PermissionRepository permissionRepository;

    public Role createRole(RoleRequest request, String token){
        User creator = userContextService.getCurrentUserFromToken(token);

        Role newRole = Role.builder()
                .name(request.getName())
                .creator(creator)
                .clientApp(creator.getClientApp())
                .build();

        return roleRepository.save(newRole);
    }

    public List<Role> getAllRoles(String currentToken){
        User currentUser = userContextService.getCurrentUserFromToken(currentToken);

        boolean isSudo = currentUser.getRoles().stream()
                .anyMatch(r -> r.getName().equals("SUDO"));

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
                .anyMatch(r -> r.getName().equals("SUDO"));
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
                .anyMatch(r -> r.getName().equals("SUDO"));

        if (!isSudo) {
            if (!roleToDelete.getClientApp().getId().equals(currentUser.getClientApp().getId())) {

                throw new RuntimeException("Acceso denegado: El rol pertenece a otra organización (Tenant).");
            }
        }

        roleRepository.delete(roleToDelete);
    }

    public Role assignPermissions(Integer roleId, PermissionAssignementRequest request, String token){
        User currentUser = userContextService.getCurrentUserFromToken(token);

        Role role = roleRepository.findById(roleId)
                .orElseThrow(()-> new RuntimeException("Rol no encontrado"));

        if(!role.getClientApp().getId().equals(currentUser.getClientApp().getId())){
            throw new RuntimeException("No tienes permisos para modificar este rol");
        }

        List<Permission> permissions = permissionRepository.findByNameIn(request.getPermissions());

        if(permissions.size() != request.getPermissions().size()){
            throw new RuntimeException("Uno o mas permisos no existen en el sistema");
        }

        role.setPermissions(permissions);
        return roleRepository.save(role);
    }
}
