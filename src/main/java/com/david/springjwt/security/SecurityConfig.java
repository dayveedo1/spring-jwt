package com.david.springjwt.security;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableWebSecurity

public class SecurityConfig  extends WebSecurityConfigurerAdapter {


    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception{
        return super.authenticationManagerBean();
    }

    public SecurityConfig(@Qualifier("appUserServiceImpl") UserDetailsService userDetailsService,
                          BCryptPasswordEncoder bCryptPasswordEncoder){
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    //Tells Spring how we want to look for users & authenticate
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    //Tells Spring how to manage sessions for security
    //By default, it uses stateful session and keep track with cookies
    //but we override so we can use Tokens and don't keep track with cookies
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //customizing the default spring endpoint for login
        CustomAuthFilter customAuthFilter = new CustomAuthFilter(authenticationManagerBean());
        customAuthFilter.setFilterProcessesUrl("/api/login");

        http
                .csrf().disable()

                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests().antMatchers("/api/login/**", "/api/user/saveUser**", "/api/user/register","/api/user/token/refreshToken/**", "/swagger-ui.html", "/swagger-ui/**", "/webjars/**", "/swagger-resources","/swagger-resources/**", "/configuration/ui", "/configuration/security", "/v2/api-docs", "/v3/api-docs").permitAll()
                .and()
                .authorizeRequests().antMatchers(GET, "/api/user/**").hasAuthority("ROLE_USER")
                .and()
                .authorizeRequests().antMatchers(POST,  "/api/user/saveRole/**", "/api/user/addRoleToUser").hasAuthority("ROLE_ADMIN") //"/api/user/save/**",
                .and()
                .authorizeRequests().anyRequest().authenticated()
                .and()
                .addFilter(customAuthFilter);

        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);


    }
}
