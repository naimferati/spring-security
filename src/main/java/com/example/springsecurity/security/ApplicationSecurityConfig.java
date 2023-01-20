package com.example.springsecurity.security;

import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {

    //We cannot extend the WebSecurityConfigurerAdapter because it is deprecated, so we have to do in this way!

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .httpBasic()
                .and()
                .authorizeHttpRequests((authz) -> authz
                        .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                        //requestMatcher is the same as antMatcher (antMatcher was the name in previous versions)
                        .requestMatchers("/", "/index.html", "/css/*", "/js/*")
                        .permitAll()
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

}
