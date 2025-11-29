package security.demo_jwt.auth;

import lombok.Data;

@Data
public class NewPasswordRequest {

    private String token;
    private String newPassword;
}
