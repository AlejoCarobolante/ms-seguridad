package security.demo_jwt.modules.user.dto;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class UserResponse {
    private Integer id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private boolean isLocked;
    private boolean isEnabled;
    private List<String> roles;
}