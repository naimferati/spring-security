package com.example.springsecurity.security;

import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.example.springsecurity.security.ApplicationUserRole.*;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    //We cannot extend the WebSecurityConfigurerAdapter because it is deprecated, so we have to do in this way!

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .httpBasic()
                .and()
                .authorizeHttpRequests((authz) -> authz
                                .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                                //requestMatcher is the same as antMatcher (antMatcher was the name in previous versions)
                                //the order of requestMatchers METERS!
                                .requestMatchers("/", "/index.html", "/css/*", "/js/*").permitAll()
                                .requestMatchers("/api/**").hasRole(STUDENT.name())
                                //We can implement privileges/authorities via requestMatchers in the way below, but also with annotation (the preferred way)
//                        .requestMatchers(HttpMethod.DELETE, "/management/api/**").hasAnyAuthority(STUDENT_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.POST, "/management/api/**").hasAnyAuthority(STUDENT_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.PUT, "/management/api/**").hasAnyAuthority(STUDENT_WRITE.getPermission())
//                        .requestMatchers("/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
                                .anyRequest()
                                .authenticated()
                )
                .httpBasic(withDefaults());

        //It can be done in this way also!!

/*                .authorizeHttpRequests()
                .requestMatchers("/", "index", "/css/*", "/js/*")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();*/

        return http.build();
    }


    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails bejtullaFeratiUser = User.builder()
                .username("bejtullaferati")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) // Spring uses this as ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails naimFeratiUser = User.builder()
                .username("naimferati")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails emirKrasniqiUser = User.builder()
                .username("emirkrasniqi")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMIN_TRAINEE.name()) // ROLE_ADMIN_TRAINEE
                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                bejtullaFeratiUser,
                naimFeratiUser,
                emirKrasniqiUser

        );
    }

}
