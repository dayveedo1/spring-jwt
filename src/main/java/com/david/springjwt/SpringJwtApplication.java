package com.david.springjwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SpringJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtApplication.class, args);
	}

	@Bean
	BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

//	@Bean
//	CommandLineRunner run(AppUserService service){
//		return args -> {
//			service.saveRole(new Role(null, "ROLE_USER"));
//			service.saveRole(new Role(null, "ROLE_MANAGER"));
//			service.saveRole(new Role(null, "ROLE_ADMIN"));
//			service.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
////
////
////			service.saveUser(new AppUser(null, "Cole Amadi", "cole47", "1234", new ArrayList<>()));
////			service.saveUser(new AppUser(null, "Hitman", "hitman", "1234", new ArrayList<>()));
////			service.AddRoleToUser("hitman", "ROLE_USER");
////			service.AddRoleToUser("cole47", "ROLE_ADMIN");
////			service.AddRoleToUser("cole47", "ROLE_USER");
//		};
//	}

}
