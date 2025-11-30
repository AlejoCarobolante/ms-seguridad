package security.demo_jwt.Domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientAppRepository extends JpaRepository<ClientApp, Integer> {
    Optional<ClientApp> findByApiKey(String apiKey);
}
