package security.demo_jwt.domain;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(String name);
    Optional<Role> findById(int Id);
    Optional<Role> findByNameOrId(String name, int Id);
    List<Role> findAllByClientAppId(Integer clientAppId);

}