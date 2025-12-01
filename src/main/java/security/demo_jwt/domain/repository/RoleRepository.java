package security.demo_jwt.domain.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import security.demo_jwt.domain.model.Role;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(String name);
    Optional<Role> findById(int Id);
    Optional<Role> findByNameOrId(String name, int Id);
    List<Role> findAllByClientAppId(Integer clientAppId);

}