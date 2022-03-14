package com.david.springjwt.service;

import com.david.springjwt.dto.RegisterDto;
import com.david.springjwt.model.AppUser;
import com.david.springjwt.model.Role;
import org.springframework.data.domain.Page;

import java.util.List;

public interface AppUserService {

    //AppUser saveUser(AppUser appUser);
    AppUser saveUser(RegisterDto registerDto);
    AppUser getUser(String username);
    Page<AppUser> getAllUsers();


    Role saveRole(Role role);
    List<Role> getAllRoles();
    Role getRoleByRoleName(String roleName);
    void AddRoleToUser(String username, String roleName);
}
