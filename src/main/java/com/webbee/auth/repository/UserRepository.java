package com.webbee.auth.repository;

import com.webbee.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Репозиторий для работы с сущностью User
 */
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Находит пользователя по имени
     */
    Optional<User> findByUsername(String username);

    /**
     * Находит пользователя по email
     */
    Optional<User> findByEmail(String email);

}
