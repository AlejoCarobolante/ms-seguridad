package security.demo_jwt.modules.auth.dto;

import java.util.Date;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import security.demo_jwt.core.validation.StrongPassword;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    @NotBlank(message = "El nombre de usuario es obligatorio.")
    String username;

    @StrongPassword
    String password;

    @NotBlank(message = "El nombre es obligatorio.")
    String firstName;

    @NotBlank(message = "El apellido es obligatorio.")
    String lastName;

    @NotNull(message = "La fecha de nacimiento es obligatoria.")
    Date dateOfBirth;

    @NotBlank(message = "El credential es obligatorio.")
            @Email(message = "El formato del credential no es valido.")
    String email;
}
