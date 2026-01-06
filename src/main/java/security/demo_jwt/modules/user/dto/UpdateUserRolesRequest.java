package security.demo_jwt.modules.user.dto;

import lombok.Data;
import java.util.List;

@Data
public class UpdateUserRolesRequest {
    private List<Integer> roleIds;
}