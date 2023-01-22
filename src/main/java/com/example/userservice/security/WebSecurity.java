package com.example.userservice.security;

import com.example.userservice.service.UserService;
import jakarta.servlet.Filter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(enforceUniqueMethods = false)
@EnableWebSecurity
@AllArgsConstructor
public class WebSecurity {
    private final UserService userService;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final Environment env;

    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        return this.authenticationConfiguration.getAuthenticationManager();
    }
    @Bean
    public static BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.csrf().disable();
        http.authorizeHttpRequests().requestMatchers("/**")
                        .permitAll()
                        .and()
                        .addFilter(getAuthenticationFilter());

        http.headers().frameOptions().disable();
        return http.build();
    }

    @Bean
    public AuthenticationFilter getAuthenticationFilter() throws Exception{
        AuthenticationFilter authenticationFilter =
                new AuthenticationFilter(authenticationManager(), userService, env);
        authenticationFilter.setAuthenticationManager(authenticationManager());
        return authenticationFilter;
    }
    @Bean
    AuthenticationManager authenticationManager(AuthenticationManagerBuilder builder) throws Exception {
        return builder.userDetailsService(userService).passwordEncoder(passwordEncoder()).and().build();
    }

}
