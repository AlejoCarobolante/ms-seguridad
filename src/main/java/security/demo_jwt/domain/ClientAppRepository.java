package security.demo_jwt.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientAppRepository extends JpaRepository<ClientApp, Integer> {
    Optional<ClientApp> findByApiKey(String apiKey);
}
