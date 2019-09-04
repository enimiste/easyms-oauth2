package com.easyms.security.repository;

import com.easyms.security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author khames.
 */
@Repository
public interface OAuthUserRepository extends JpaRepository<User, String> {

    Optional<User> findByLogin(String login);
}
