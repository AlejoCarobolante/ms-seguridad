package security.demo_jwt.domain.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import security.demo_jwt.domain.model.ClientApp;
import security.demo_jwt.domain.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    @Query("SELECT u FROM User u WHERE (u.email = :credential OR u.username = :credential) AND u.clientApp = :app")
    Optional<User> findByCredentialAndApp(@Param("credential") String credential, @Param("app") ClientApp app);
    Optional<User> findByVerificationCode(String verificationCode);
    Optional<User> findByResetPasswordToken(String token);
    Optional<User> findById(Integer id);
    Page<User> findAllByClientApp(ClientApp clientApp, Pageable pageable);
}
