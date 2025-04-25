package com.hospital.api_gateway.controller;

import com.hospital.api_gateway.jwt.JwtUtil;
import com.hospital.api_gateway.dto.LoginRequest;
import com.hospital.api_gateway.dto.LoginResponse;
import com.hospital.api_gateway.dto.SignupRequest;
import com.hospital.api_gateway.model.User;
import com.hospital.api_gateway.repository.UserRepository;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        logger.info("Processing login for username: {}", request.getUsername());
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> {
                    logger.warn("Login failed: User {} not found", request.getUsername());
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
                });

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            logger.warn("Login failed: Invalid password for {}", request.getUsername());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        List<SimpleGrantedAuthority> authorities = Arrays.stream(user.getRoles().split(","))
                .map(String::trim)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        String token = jwtUtil.generateToken(user.getUsername(), authorities);
        logger.debug("Generated token for {}: {}", user.getUsername(), token);

        LoginResponse response = new LoginResponse();
        response.setToken(token);
        return response;
    }

    @PostMapping("/signup")
    public LoginResponse signup(@Valid @RequestBody SignupRequest request) {
        logger.info("Processing signup for username: {}", request.getUsername());
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            logger.warn("Signup failed: Username {} already exists", request.getUsername());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username already exists");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRoles(String.join(",", request.getRoles()));

        userRepository.save(user);
        logger.debug("Saved user: {}", user.getUsername());

        List<SimpleGrantedAuthority> authorities = request.getRoles().stream()
                .map(String::trim)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        String token = jwtUtil.generateToken(user.getUsername(), authorities);
        logger.debug("Generated token for {}: {}", user.getUsername(), token);

        LoginResponse response = new LoginResponse();
        response.setToken(token);
        return response;
    }
}