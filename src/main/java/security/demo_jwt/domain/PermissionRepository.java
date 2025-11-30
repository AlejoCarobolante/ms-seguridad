package security.demo_jwt.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface PermissionRepository extends JpaRepository<Permission, Integer> {

    List<Permission> findByNameIn(Collection<String> names);
    Optional<Permission> findByName(String name);
}
