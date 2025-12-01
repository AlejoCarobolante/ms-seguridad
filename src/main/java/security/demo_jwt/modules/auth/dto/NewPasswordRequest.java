package security.demo_jwt.modules.auth.dto;

import lombok.Data;

@Data
public class NewPasswordRequest {

    private String token;
    private String newPassword;
}
