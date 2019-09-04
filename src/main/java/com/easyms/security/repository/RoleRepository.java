package com.easyms.security.repository;

import com.easyms.security.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author khames.
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, String> {

    List<Role> findByIdIn(List<String> ids);

    List<Role> findByNameIn(List<String> names);
}
