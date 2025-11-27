package security.demo_jwt.auth;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor


public class AuthController {

    @PostMapping(value = "login")
    public String login() {
        return "Login successful";
    }    

    @PostMapping(value = "register")
    public String register() {
        return "Registration successful";
    }
}
