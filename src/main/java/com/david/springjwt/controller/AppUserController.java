package com.david.springjwt.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.david.springjwt.dto.RegisterDto;
import com.david.springjwt.dto.RoleToUserDto;
import com.david.springjwt.model.AppUser;
import com.david.springjwt.model.Role;
import com.david.springjwt.service.AppUserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@Api( tags = "user")
@RequestMapping("/api/user")
public class AppUserController {


    private final AppUserService appUserService;
    private final AuthenticationManager authenticationManager;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    Logger log = LoggerFactory.getLogger(AppUserController.class);

    public AppUserController(AppUserService appUserService, AuthenticationManager authenticationManager, BCryptPasswordEncoder bCryptPasswordEncoder){
        this.appUserService = appUserService;
        this.authenticationManager = authenticationManager;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

//    @ApiOperation("To login")
//    @PostMapping("/login")
//    public ResponseEntity<?> login(@RequestBody @Valid AuthRequest request){
//        try{
//
//            Authentication authentication = authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
//
//            User user = (User) authentication.getPrincipal();
//            Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); //  for production, "secret not to be set here
//            String access_token = JWT.create()
//                    .withSubject(user.getUsername())
//                    .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
//                    .withIssuer("Spring-JWT")
//                    .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
//                    .sign(algorithm);
//
//            String refresh_token = JWT.create()
//                    .withSubject(user.getUsername())
//                    .withExpiresAt(new Date(Integer.MAX_VALUE))
//                    .withIssuer("Spring-JWT")
//                    .sign(algorithm);
//
//            Map<String, String> tokens = new HashMap<>();
//            tokens.put("access_token", access_token);
//            tokens.put("refresh_token", refresh_token);
//
//            return ResponseEntity.ok().header(AUTHORIZATION).body(tokens);
////            );
//        } catch (BadCredentialsException ex){
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
//        }
//    }

    @ApiOperation("To return list of users")
    @GetMapping("/getAllUsers")
    public ResponseEntity <Page<AppUser>> getAllUsers(){
        return ResponseEntity.ok().body(appUserService.getAllUsers());
    }

//    @ApiOperation("To register")
//    @PostMapping("/register")
//    public ResponseEntity<AppUser> register(@RequestBody RegisterDto registerDto){
//        AppUser user = new AppUser();
//        user.setName(registerDto.getName());
//        user.setUsername(registerDto.getUsername());
//        user.setPassword(bCryptPasswordEncoder.encode(registerDto.getPassword()));
//
//        List<Role> roles = appUserService.getAllRoles();
//        List<Role> rolesToAdd = new ArrayList<>();
//        for (Role role : roles) {
//            if(role.getRoleName().equals("ROLE_USER")){
//                rolesToAdd.add(role);
//            }
//        }
//
//        user.setRoles(rolesToAdd);
//        return ResponseEntity.ok().body(appUserService.saveUser(user));
//
//    }

//    @ApiOperation("To save a user")
//    @PostMapping("/saveUser")
//    public ResponseEntity<AppUser> saveUser (@RequestBody AppUser appUser){
//        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/saveUser").toUriString());
//        return ResponseEntity.created(uri).body(appUserService.saveUser(appUser));
//    }

    @ApiOperation("To save a user")
    @PostMapping("/saveUser")
    public ResponseEntity<AppUser> saveUser (@RequestBody RegisterDto registerDto){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/saveUser").toUriString());
        return ResponseEntity.created(uri).body(appUserService.saveUser(registerDto));
    }

    @ApiOperation("To save a role")
    @PostMapping("/saveRole")
    public ResponseEntity<Role> saveRole(@RequestBody Role role){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/saveRole").toUriString());
        return ResponseEntity.created(uri).body(appUserService.saveRole(role));
    }

    @ApiOperation("To add role to user")
    @PostMapping("/addRoleToUser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserDto dto){
        appUserService.AddRoleToUser(dto.getUsername(), dto.getRoleName());
        return ResponseEntity.ok().build();
    }

    @ApiOperation("To generate token using refresh token")
    @GetMapping("/token/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){

            try{
                //to get the actual token, we remove the prefix "bearer"
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);

                //get the username & roles from the token and decode
                String username = decodedJWT.getSubject();  //username
                AppUser user = appUserService.getUser(username);

                String access_token = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getRoleName).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);

                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

            } catch (Exception ex){
                log.error("Error logging in: {}", ex.getMessage());
                response.setHeader("error", ex.getMessage());
                response.setStatus(FORBIDDEN.value());
                //response.sendError(FORBIDDEN.value);
                Map<String, String> error = new HashMap<>();
                error.put("error_message", ex.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);

            }

        }else {
            throw new RuntimeException("Refresh Token Invalid");
        }
    }
}
