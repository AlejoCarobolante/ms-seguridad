package security.demo_jwt.modules.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import security.demo_jwt.core.validation.StrongPassword;

@Data
public class ChangePasswordRequest {

    @NotBlank
    private String currentPassword;

    @StrongPassword
    private String newPassword;
}
