package security.demo_jwt.modules.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {

    @JsonProperty("access_token")
    String accessToken;

    @JsonProperty("refresh_token")
    String refreshToken;

    @JsonProperty("mfa_required")
    boolean mfaRequired;

    @JsonProperty("mfa_setup_required")
    boolean mfaSetupRequired;

    @JsonProperty("mfa_enabled")
    private boolean mfaEnabled;

    @JsonProperty("temp_token")
    String tempToken;
}
