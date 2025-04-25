package com.hospital.api_gateway.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${jwt.secret}")
    private String secret;

    private static Key signingKey;

    @PostConstruct
    public void init() {
        logger.info("JwtUtil initialized with secret (first 5 chars): {}", secret != null ? secret.substring(0, Math.min(5, secret.length())) : "null");
        signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        logger.debug("Signing key initialized for HS256, hash: {}", Arrays.hashCode(signingKey.getEncoded()));
    }

    public String extractUsername(String token) {
        logger.debug("Extracting username from token");
        try {
            return getClaims(token).getSubject();
        } catch (Exception e) {
            logger.error("Error extracting username: {}", e.getMessage());
            throw e;
        }
    }

    public List<String> extractRoles(String token) {
        logger.debug("Extracting roles from token");
        try {
            Claims claims = getClaims(token);
            List<?> roles = claims.get("roles", List.class);
            return roles.stream().map(Object::toString).collect(Collectors.toList());
        } catch (Exception e) {
            logger.error("Error extracting roles: {}", e.getMessage());
            throw e;
        }
    }

    public boolean validateToken(String token, String username) {
        logger.debug("Validating token for username: {}", username);
        try {
            Claims claims = getClaims(token);
            String tokenUsername = claims.getSubject();
            Date expiration = claims.getExpiration();
            boolean isValid = tokenUsername.equals(username) && expiration.after(new Date());
            logger.debug("Token validation: usernameMatch={}, notExpired={}, isValid={}",
                    tokenUsername.equals(username), expiration.after(new Date()), isValid);
            return isValid;
        } catch (JwtException e) {
            logger.error("JWT validation failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during token validation: {}", e.getMessage());
            throw e;
        }
    }

    private Claims getClaims(String token) {
        logger.debug("Parsing token claims with secret (first 5 chars): {}, key hash: {}",
                secret.substring(0, Math.min(5, secret.length())), Arrays.hashCode(signingKey.getEncoded()));
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            logger.error("Failed to parse JWT claims: {}", e.getMessage());
            throw e;
        }
    }

    public String generateToken(String username, List<SimpleGrantedAuthority> authorities) {
        logger.debug("Generating token for username: {}, authorities: {}", username, authorities);
        try {
            List<String> roles = authorities.stream()
                    .map(SimpleGrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            return Jwts.builder()
                    .setSubject(username)
                    .claim("roles", roles)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour
                    .signWith(signingKey, SignatureAlgorithm.HS256)
                    .compact();
        } catch (Exception e) {
            logger.error("Error generating token: {}", e.getMessage());
            throw e;
        }
    }
}