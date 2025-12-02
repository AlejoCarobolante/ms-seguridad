package security.demo_jwt.modules.rbac.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.Set;

@Data
public class PermissionAssignementRequest {
    @NotEmpty(message = "La lista de permisos no puede estar vacia")
    private Set<String> permissions;
}
