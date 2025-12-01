package security.demo_jwt.modules.user.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SessionResponse {
    Integer id;
    String deviceInfo;
    String ipAdress;
    boolean isCurrentSession;
}
