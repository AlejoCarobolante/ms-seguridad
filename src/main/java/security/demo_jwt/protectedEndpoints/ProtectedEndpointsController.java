package security.demo_jwt.protectedEndpoints;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class ProtectedEndpointsController {

    @PostMapping(value = "protected")
    public String welcome() {   
        return "Welcome to the protected endpoint!";
    }
}
