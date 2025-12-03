package security.demo_jwt.modules.auth.dto;

import lombok.Data;
import security.demo_jwt.core.validation.StrongPassword;

@Data
public class NewPasswordRequest {

    private String token;

    @StrongPassword
    private String newPassword;
}
