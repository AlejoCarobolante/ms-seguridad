package security.demo_jwt.modules.user.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.Date;

@Data
public class UpdateProfileRequest {

    @NotBlank(message = "El nombre no puede estar vacio")
    private String firstName;

    @NotBlank(message = "El apellido no puede estar vacio")
    private String lastName;

    private Date dateOfBirth;
}
