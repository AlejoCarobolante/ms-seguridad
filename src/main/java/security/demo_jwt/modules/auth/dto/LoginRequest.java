package security.demo_jwt.modules.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {

    @NotBlank(message = "Las credenciales no pueden estar vacías")
    String credential;

    @NotBlank(message = "La contraseña no puede estar vacía")
    String password;
}
