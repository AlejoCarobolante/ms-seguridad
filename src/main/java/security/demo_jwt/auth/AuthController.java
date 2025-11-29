package security.demo_jwt.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor


public class AuthController {

    private final AuthService authService;

    @PostMapping(value = "login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {

        return ResponseEntity.ok(authService.login(request));
    }    

    @PostMapping(value = "register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {

        return ResponseEntity.ok(authService.register(request));
    }

    @GetMapping(value = "verify")
    public ModelAndView verify(@RequestParam String code){
        authService.verifyUser(code);
        return new ModelAndView("verified-success");
    }

    @PostMapping(value = "forgot-password")
    public ResponseEntity<String> recoverPassword(@RequestBody RecoverPasswordRequest request){
        authService.forgotPassword(request.getEmail());
        return ResponseEntity.ok("Se ha enviado un enlace al correo.");
    }

    @GetMapping(value = "recover-password")
    public ModelAndView showChangePasswordPage(@RequestParam String token){
        ModelAndView mav = new ModelAndView("change-password");
        mav.addObject("token", token);
        return mav;
    }

    @PostMapping(value = "reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody NewPasswordRequest request){
        authService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok("Contraseña actualizada correctamente.");
    }

    @PostMapping(value = "refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(HttpServletRequest request){
        return ResponseEntity.ok(authService.refreshToken(request));
    }
}
