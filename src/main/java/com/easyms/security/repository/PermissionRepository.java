package com.easyms.security.repository;

import com.easyms.security.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author khames.
 */
@Repository
public interface PermissionRepository extends JpaRepository<Permission, String> {

}
