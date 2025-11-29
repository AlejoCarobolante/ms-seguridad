package security.demo_jwt.auth;


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
