package com.david.springjwt.repo;

import com.david.springjwt.model.AppUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepo extends JpaRepository<AppUser, Long> {

    AppUser findByUsername(String username);
    Page<AppUser> findAll(Pageable pageable);
}
