package security.demo_jwt.domain.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.demo_jwt.domain.model.ClientApp;

import java.util.Optional;

public interface ClientAppRepository extends JpaRepository<ClientApp, Integer> {
    Optional<ClientApp> findByApiKey(String apiKey);
}
