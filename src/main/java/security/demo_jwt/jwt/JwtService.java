package security.demo_jwt.jwt;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    public String getToken(UserDetails user) {
        return null;
    }


}
