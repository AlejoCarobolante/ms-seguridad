package security.demo_jwt.domain.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import security.demo_jwt.domain.model.PasswordHistory;

import java.util.List;

public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, Integer> {

    @Query("SELECT ph FROM PasswordHistory ph WHERE ph.user.id = :userId ORDER BY ph.createdAt DESC")
    List<PasswordHistory> findLastPasswords(Integer userId);
}
