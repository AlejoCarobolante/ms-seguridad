package security.demo_jwt.role;


import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RoleRequest {

    @NotBlank(message = "El nombre del rol es obligatorio")
    String name;

    String description;
}
