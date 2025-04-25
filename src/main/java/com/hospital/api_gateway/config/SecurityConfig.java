package com.hospital.api_gateway.config;

import com.hospital.api_gateway.jwt.JwtAuthenticationFilter;
import com.hospital.api_gateway.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .addFilterBefore(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/auth/login", "/auth/signup").permitAll()
                        .pathMatchers("/patients/**", "/appointments/**", "/notifications/**").authenticated()
                        .anyExchange().denyAll()
                )
                .exceptionHandling()
                .authenticationEntryPoint((exchange, ex) -> {
                    logger.error("Authentication failed for path {}: {}", exchange.getRequest().getPath(), ex.getMessage());
                    return Mono.fromRunnable(() -> exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED));
                })
                .accessDeniedHandler((exchange, ex) -> {
                    logger.error("Access denied for path {}: {}", exchange.getRequest().getPath(), ex.getMessage());
                    return Mono.fromRunnable(() -> exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN));
                });
        return http.build();
    }

    @Bean
    public ReactiveUserDetailsService userDetailsService() {
        return username -> Mono.defer(() -> {
            return userRepository.findByUsername(username)
                    .map(user -> new User(
                            user.getUsername(),
                            user.getPassword(),
                            Arrays.stream(user.getRoles().split(","))
                                    .map(SimpleGrantedAuthority::new)
                                    .collect(Collectors.toList())
                    ))
                    .map(Mono::just)
                    .orElseGet(() -> Mono.error(new UsernameNotFoundException("User not found: " + username)));
        });
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}