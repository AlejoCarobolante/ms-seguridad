package security.demo_jwt.auth;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class LoginAttemptService {

    static final int maxAttempts = 3;
    static final int kickDurationMin = 5;

    private final Cache<String, Integer> attemptsCache = Caffeine.newBuilder()
            .expireAfterWrite(kickDurationMin, TimeUnit.MINUTES)
            .build();

    public void loginFailed(String email){

        int attempts = attemptsCache.get(email, key -> 0);
        attempts ++;

        attemptsCache.put(email, attempts);

        System.out.println("Intento fallido numero " + attempts + "para " + email);
    }

    public boolean isBlocked(String email){

        int attempts = attemptsCache.get(email, key -> 0);
        return attempts >= maxAttempts;
    }

    public void loginSucceded(String email){
        attemptsCache.invalidate(email);
    }
}
