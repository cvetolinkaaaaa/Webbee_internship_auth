package com.webbee.auth.repository;

import com.webbee.auth.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Репозиторий для работы с сущностью Role.
 */
public interface RoleRepository extends JpaRepository<Role, Long> {

    /**
     * Находит роль по её наименованию.
     */
    Optional<Role> findByName(String name);

}
