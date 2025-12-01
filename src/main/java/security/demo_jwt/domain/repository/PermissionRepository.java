package security.demo_jwt.domain.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.demo_jwt.domain.model.Permission;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface PermissionRepository extends JpaRepository<Permission, Integer> {

    List<Permission> findByNameIn(Collection<String> names);
    Optional<Permission> findByName(String name);
}
