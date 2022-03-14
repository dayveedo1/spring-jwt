package com.david.springjwt.service;

import com.david.springjwt.dto.RegisterDto;
import com.david.springjwt.model.AppUser;
import com.david.springjwt.model.Role;
import com.david.springjwt.repo.AppUserRepo;
import com.david.springjwt.repo.RoleRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;

@Service
@Transactional
public class AppUserServiceImpl implements AppUserService, UserDetailsService {

    private final AppUserRepo appUserRepo;
    private final RoleRepo roleRepo;

    private final BCryptPasswordEncoder passwordEncoder;

    Logger log = LoggerFactory.getLogger(AppUserServiceImpl.class);

    public AppUserServiceImpl(AppUserRepo appUserRepo, RoleRepo roleRepo, BCryptPasswordEncoder passwordEncoder){
        this.appUserRepo = appUserRepo;
        this.roleRepo = roleRepo;
        this.passwordEncoder = passwordEncoder;
    }

    //method Spring security uses to load users from DB
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       //fetch user from DB
        AppUser appUser = appUserRepo.findByUsername(username);

        if (appUser == null){
            log.error("User not found in DB");
            throw new UsernameNotFoundException("User not found in DB");
        }
        else{
            log.info("User found in DB: {}", username);
        }

        //compose the role authorities granted to user and return the username, password & authorities
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        appUser.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
        });

        return new User(appUser.getUsername(), appUser.getPassword(), authorities);
    }

//    @Override
//    public AppUser saveUser(AppUser appUser) {
//        log.info("Saving new User {} in DB", appUser.getUsername());
//        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
//        return appUserRepo.save(appUser);
//    }

    @Override
    public AppUser saveUser(RegisterDto registerDto) {
        log.info("Saving new User {} in DB", registerDto.getUsername());

        AppUser user = new AppUser();

        Random rand = new Random();

//        System.out.printf("%04d%n", );
        user.setId(rand.nextLong());
        user.setUsername(registerDto.getUsername());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        user.setName(registerDto.getName());

        List<Role> roles = new ArrayList<>();
        Role getRoleUser = getRoleByRoleName("ROLE_USER");
        roles.add(getRoleUser);

        user.setRoles(roles);

        Role getRoleName = getRoleByRoleName("ROLE_USER");
        AddRoleToUser(user.getUsername(), getRoleName.toString());

        return appUserRepo.save(user);


//        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
//        return appUserRepo.save(appUser);
    }

    @Override
    public AppUser getUser(String username) {
        log.info("Retrieving User {} from DB", username);
        return appUserRepo.findByUsername(username);
    }

    @Override
    public Page<AppUser> getAllUsers() {

        log.info("Fetching All Users from DB");
        Pageable paging = PageRequest.of(0, 20);
       return appUserRepo.findAll(paging);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new Role {} in DB", role.getRoleName());
        return roleRepo.save(role);
    }

    @Override
    public List<Role> getAllRoles() {
        return roleRepo.findAll();
    }

    @Override
    public Role getRoleByRoleName(String roleName) {
        return roleRepo.findByRoleName(roleName);
    }

    @Override
    public void AddRoleToUser(String username, String roleName) {
        AppUser user = appUserRepo.findByUsername(username);
        Role role = roleRepo.findByRoleName(roleName);

        if (user != null){
            user.getRoles().add(role);
        }

    }


}
