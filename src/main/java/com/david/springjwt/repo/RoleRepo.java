package com.david.springjwt.repo;

import com.david.springjwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {

    Role findByRoleName(String roleName);
}
