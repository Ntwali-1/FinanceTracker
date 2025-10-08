package com.example.FinanceTracker.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * JWT Service for handling JWT token operations
 *
 * This service provides comprehensive JWT functionality including:
 * - Token generation with custom claims
 * - Token validation and parsing
 * - Username and authorities extraction
 * - Refresh token support
 * - Configurable expiration times
 *
 * Required Configuration Properties:
 * - application.security.jwt.secret-key: Base64-encoded secret key for signing
 * - application.security.jwt.expiration: Access token expiration time in milliseconds
 * - application.security.jwt.refresh-token.expiration: Refresh token expiration time
 *
 * Usage:
 * 1. Update package name to match your project
 * 2. Configure JWT properties in application.yml/properties
 * 3. Inject this service where JWT operations are needed
 * 4. Generate tokens on successful authentication
 * 5. Validate tokens in authentication filters
 *
 * Example application.yml configuration:
 * application:
 *   security:
 *     jwt:
 *       secret-key: "your-base64-encoded-secret-key-here"
 *       expiration: 86400000  # 24 hours in milliseconds
 *       refresh-token:
 *         expiration: 604800000  # 7 days in milliseconds
 */
@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    // JWT configuration properties from application.yml/properties
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    // Constants for JWT claims
    private static final String AUTHORITIES_CLAIM = "authorities";
    private static final String TOKEN_TYPE_CLAIM = "token_type";

    /**
     * Extract username (subject) from JWT token
     *
     * @param token JWT token string
     * @return username/email from the token, null if extraction fails
     */
    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (Exception e) {
            logger.error("Failed to extract username from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extract authorities from JWT token
     *
     * @param token JWT token string
     * @return list of authority strings, empty list if extraction fails
     */
    public List<String> extractAuthorities(String token) {
        try {
            List<?> authorities = extractClaim(token, claims -> claims.get(AUTHORITIES_CLAIM, List.class));
            return authorities != null
                    ? authorities.stream().map(Object::toString).collect(Collectors.toList())
                    : List.of();
        } catch (Exception e) {
            logger.error("Failed to extract authorities from token: {}", e.getMessage());
            return List.of();
        }
    }

    /**
     * Extract expiration date from JWT token
     *
     * @param token JWT token string
     * @return expiration date
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extract any claim from JWT token using a claims resolver function
     *
     * @param token JWT token string
     * @param claimsResolver function to extract specific claim
     * @return extracted claim value
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Generate access token for authenticated user
     * Includes user authorities in the token claims
     *
     * @param userDetails authenticated user details
     * @return JWT access token string
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();

        // Add authorities to token claims
        extraClaims.put(AUTHORITIES_CLAIM, userDetails.getAuthorities().stream()
                .map(Object::toString)
                .collect(Collectors.toList()));

        // Add token type for identification
        extraClaims.put(TOKEN_TYPE_CLAIM, "access");

        return generateToken(extraClaims, userDetails);
    }

    /**
     * Generate access token with custom extra claims
     *
     * @param extraClaims additional claims to include in the token
     * @param userDetails authenticated user details
     * @return JWT access token string
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Generate refresh token for token renewal
     * Contains minimal claims for security
     *
     * @param userDetails authenticated user details
     * @return JWT refresh token string
     */
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> refreshClaims = new HashMap<>();
        refreshClaims.put(TOKEN_TYPE_CLAIM, "refresh");

        logger.debug("Generating refresh token for user: {}", userDetails.getUsername());
        return buildToken(refreshClaims, userDetails, refreshExpiration);
    }

    /**
     * Validate JWT token against user details
     * Checks both token integrity and expiration
     *
     * @param token JWT token string
     * @param userDetails user details to validate against
     * @return true if token is valid, false otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            boolean isValid = username != null
                    && username.equals(userDetails.getUsername())
                    && !isTokenExpired(token);

            logger.debug("Token validation for user {}: {}", username, isValid);
            return isValid;
        } catch (Exception e) {
            logger.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if JWT token is expired
     *
     * @param token JWT token string
     * @return true if token is expired, false otherwise
     */
    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            logger.error("Failed to check token expiration: {}", e.getMessage());
            return true; // Treat as expired if validation fails
        }
    }

    /**
     * Get remaining time until token expiration
     *
     * @param token JWT token string
     * @return milliseconds until expiration, 0 if expired or invalid
     */
    public long getTokenRemainingTime(String token) {
        try {
            Date expiration = extractExpiration(token);
            long remaining = expiration.getTime() - System.currentTimeMillis();
            return Math.max(0, remaining);
        } catch (Exception e) {
            logger.error("Failed to calculate token remaining time: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * Extract all claims from JWT token
     *
     * @param token JWT token string
     * @return all claims from the token
     * @throws RuntimeException if token parsing fails
     */
    Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            logger.error("Failed to extract claims from token: {}", e.getMessage());
            throw e; // Let the calling code handle the exception
        }
    }

    /**
     * Build JWT token with specified claims, user details, and expiration
     *
     * @param extraClaims additional claims to include
     * @param userDetails user details for the token subject
     * @param expiration expiration time in milliseconds
     * @return JWT token string
     */
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        logger.debug("Generating token for user: {} with expiration: {}",
                userDetails.getUsername(), expiration);

        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Get the signing key for JWT operations
     * Decodes the Base64-encoded secret key from configuration
     *
     * @return HMAC signing key
     * @throws IllegalStateException if secret key configuration is invalid
     */
    private Key getSignInKey() {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(secretKey);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid Base64 secret key: {}", e.getMessage());
            throw new IllegalStateException("Invalid JWT secret key configuration", e);
        }
    }

    // Utility methods for token management

    /**
     * Extract token type from JWT (access, refresh, etc.)
     *
     * @param token JWT token string
     * @return token type string, "unknown" if not present
     */
    public String extractTokenType(String token) {
        try {
            return extractClaim(token, claims -> claims.get(TOKEN_TYPE_CLAIM, String.class));
        } catch (Exception e) {
            logger.error("Failed to extract token type: {}", e.getMessage());
            return "unknown";
        }
    }

    /**
     * Check if token is a refresh token
     *
     * @param token JWT token string
     * @return true if it's a refresh token
     */
    public boolean isRefreshToken(String token) {
        return "refresh".equals(extractTokenType(token));
    }

    /**
     * Check if token is an access token
     *
     * @param token JWT token string
     * @return true if it's an access token
     */
    public boolean isAccessToken(String token) {
        return "access".equals(extractTokenType(token));
    }

    // Getters for configuration values (useful for testing or external access)

    public long getJwtExpiration() {
        return jwtExpiration;
    }

    public long getRefreshExpiration() {
        return refreshExpiration;
    }
}
