package security.demo_jwt.modules.auth;


import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;
import security.demo_jwt.core.security.jwt.JwtService;
import security.demo_jwt.domain.model.MfaPolicy;
import security.demo_jwt.domain.model.User;
import security.demo_jwt.modules.auth.dto.AuthResponse;
import security.demo_jwt.modules.auth.dto.MfaResponse;
import security.demo_jwt.modules.auth.dto.MfaVerificationRequest;
import security.demo_jwt.core.security.services.UserContextService;
import security.demo_jwt.domain.repository.UserRepository;


@RestController
@RequestMapping("/api/v1/mfa")
@RequiredArgsConstructor
public class TwoFactorAuthController {

    private final TwoFactorAuthService tfaService;
    private final UserContextService userContextService;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    @PostMapping("/generate")
    public ResponseEntity<MfaResponse> generate() {

        User user = userContextService.getCurrentUser();

        if (user.getClientApp().getMfaPolicy() == MfaPolicy.DISABLED) {
            throw new AccessDeniedException("MFA no disponible");
        }

        String secret = tfaService.generateNewSecret();
        String qrUri = tfaService.generateQRCodeImage(
                secret,
                user.getEmail(),
                user.getClientApp().getName()
        );

        return ResponseEntity.ok(new MfaResponse(secret, qrUri));
    }


    @PostMapping("/verify")
    public ResponseEntity<AuthResponse> verify(
            @RequestBody MfaVerificationRequest request
    ) {
        User user = userContextService.getCurrentUser();

        boolean isValid = tfaService.isOtpValid(
                user.getMfaSecret(),
                request.getCode()
        );

        if (!isValid) {
            throw new BadCredentialsException("Código MFA incorrecto");
        }

        if (!user.isMfaEnabled()) {
            user.setMfaEnabled(true);
            userRepository.save(user);
        }

        String accessToken = jwtService.getToken(user);
        String refreshToken = jwtService.getRefreshToken(user);

        return ResponseEntity.ok(
                AuthResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .mfaEnabled(true)
                        .build()
        );
    }
}
