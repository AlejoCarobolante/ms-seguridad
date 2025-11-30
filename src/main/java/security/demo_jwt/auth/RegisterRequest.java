package security.demo_jwt.auth;

import java.util.Date;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    @NotBlank(message = "El nombre de usuario es obligatorio.")
    String username;

    @NotBlank(message = "La contraseña es obligatoria.")
            @Size(min = 8, message = "La contraseña debe contener al menos 8 caracteres.")
    String password;

    @NotBlank(message = "El nombre es obligatorio.")
    String firstName;

    @NotBlank(message = "El apellido es obligatorio.")
    String lastName;

    @NotNull(message = "La fecha de nacimiento es obligatoria.")
    Date dateOfBirth;

    @NotBlank(message = "El email es obligatorio.")
            @Email(message = "El formato del email no es valido.")
    String email;
}
