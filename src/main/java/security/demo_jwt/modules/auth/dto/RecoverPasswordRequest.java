package security.demo_jwt.modules.auth.dto;

import lombok.Data;

@Data
public class RecoverPasswordRequest {

    private String email;
}
