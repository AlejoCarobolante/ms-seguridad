package security.demo_jwt.modules.user.dto;


import lombok.Builder;
import lombok.Data;

import java.util.Date;
import java.util.List;

@Data
@Builder
public class UserProfileResponse {
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private Date dateOfBirth;
    private List<String> roles;
    private String organizationName;
}
