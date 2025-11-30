package security.demo_jwt.Domain;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmailAndClientApp(String email, ClientApp app);
    Optional<User> findByUsername(String username);
    Optional<User> findByUsernameOrEmail(String username, String email);
    Optional<User> findByVerificationCode(String verificationCode);
    Optional<User> findByResetPasswordToken(String token);
    Optional<User> findById(Integer id);
    Optional<User> findByVerificationCodeAndClientApp(String code, ClientApp clientApp);
}
