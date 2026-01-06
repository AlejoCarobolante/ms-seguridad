package security.demo_jwt.modules.auth;


import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;
import security.demo_jwt.core.security.jwt.JwtService;
import security.demo_jwt.domain.model.MfaPolicy;
import security.demo_jwt.domain.model.User;
import security.demo_jwt.modules.auth.dto.AuthResponse;
import security.demo_jwt.modules.user.UserService;
import security.demo_jwt.modules.auth.dto.MfaResponse;
import security.demo_jwt.modules.auth.dto.MfaVerificationRequest;

@RestController
@RequestMapping("/api/v1/mfa")
@RequiredArgsConstructor
public class TwoFactorAuthController {

    private final TwoFactorAuthService tfaService;
    private final UserService userService;
    private final JwtService jwtService;

    @PostMapping("/generate")
    public ResponseEntity<MfaResponse> generate(@RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        User user = userService.getUserFromToken(token);

        if (user.getClientApp().getMfaPolicy() == MfaPolicy.DISABLED) {
            throw new AccessDeniedException("MFA no disponible en tenant.");
        }
        String organizationName = user.getClientApp().getName();

        String secret = tfaService.generateNewSecret();

        String qrUri = tfaService.generateQRCodeImage(secret, user.getEmail(), organizationName);

        userService.updateMfaSecret(user.getId(), secret);

        return ResponseEntity.ok(new MfaResponse(secret, qrUri));
    }

    @PostMapping("/verify")
    public ResponseEntity<AuthResponse> verify(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token,
            @RequestBody MfaVerificationRequest request
    ) {
        User user = userService.getUserFromToken(token);

        boolean isValid = tfaService.isOtpValid(user.getMfaSecret(), request.getCode());

        if (!isValid) {
            throw new BadCredentialsException("Código MFA incorrecto");
        }

        if (!user.isMfaEnabled()) {
            userService.enableMfa(user.getId());
        }

        var jwtToken = jwtService.getToken(user);
        var refreshToken = jwtService.getRefreshToken(user);

        return ResponseEntity.ok(AuthResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .mfaEnabled(true)
                .build());
    }
}
