package com.example.FinanceTracker.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT Authentication Filter
 *
 * This filter intercepts incoming HTTP requests to validate JWT tokens and set up
 * Spring Security authentication context.
 *
 * Features:
 * - Extracts JWT tokens from Authorization header
 * - Validates tokens and loads user details
 * - Sets up Spring Security authentication context
 * - Handles authorities from JWT claims
 * - Graceful error handling
 *
 * Usage:
 * 1. Update package name to match your project
 * 2. Customize SKIP_FILTER_URLS array for endpoints to skip
 * 3. Ensure JwtService and UserDetailsService beans are available
 * 4. Register this filter in your SecurityConfig
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    /**
     * URLs to skip JWT processing
     * Customize this array based on your public endpoints
     */
    private static final String[] SKIP_FILTER_URLS = {
            "/api/auth/",
            "/api/public/",
            "/swagger",
            "/v2/api-docs",
            "/v3/api-docs",
            "/error"
    };

    /**
     * Main filter logic - processes each HTTP request once
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        String method = request.getMethod();

        logger.debug("Processing request: {} {}", method, requestURI);

        // Skip JWT processing for certain requests
        if (shouldSkipFilter(request)) {
            logger.debug("Skipping JWT filter for request: {} {}", method, requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        // Extract Authorization header
        String authHeader = request.getHeader("Authorization");
        logger.debug("Authorization Header present: {}", authHeader != null);

        // Validate Authorization header format
        if (!isValidAuthHeader(authHeader)) {
            logger.debug("No valid Bearer token found, proceeding without authentication.");
            filterChain.doFilter(request, response);
            return;
        }

        // Extract JWT token (remove "Bearer " prefix)
        String jwt = authHeader.substring(7);
        logger.debug("JWT Token extracted successfully");

        // Process JWT token
        try {
            processJwtToken(jwt, request);
        } catch (Exception e) {
            logger.error("JWT authentication failed: {}", e.getMessage());
            // Continue without authentication rather than blocking the request
        }

        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Determines if the filter should be skipped for this request
     */
    private boolean shouldSkipFilter(HttpServletRequest request) {
        String method = request.getMethod();
        String requestURI = request.getRequestURI();

        // Skip OPTIONS requests (CORS preflight)
        if ("OPTIONS".equals(method)) {
            return true;
        }

        // Skip configured URLs
        for (String skipUrl : SKIP_FILTER_URLS) {
            if (requestURI.startsWith(skipUrl)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validates the Authorization header format
     */
    private boolean isValidAuthHeader(String authHeader) {
        return authHeader != null &&
                authHeader.startsWith("Bearer ") &&
                !authHeader.equals("Bearer undefined") &&
                !authHeader.equals("Bearer null");
    }

    /**
     * Processes the JWT token and sets up authentication context
     */
    private void processJwtToken(String jwt, HttpServletRequest request) {
        // Extract username from JWT
        String userEmail = jwtService.extractUsername(jwt);
        logger.debug("Extracted Email: {}", userEmail);

        // Proceed only if username is valid and no authentication exists
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Load user details from the database
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
            logger.debug("UserDetails loaded for user: {}", userDetails.getUsername());

            // Validate the JWT token
            if (jwtService.isTokenValid(jwt, userDetails)) {

                // Extract authorities from JWT claims
                List<String> authorities = jwtService.extractAuthorities(jwt);
                List<SimpleGrantedAuthority> grantedAuthorities = authorities != null
                        ? authorities.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList())
                        : List.of();

                logger.debug("Authorities extracted from JWT: {}", grantedAuthorities);

                // Create authentication token
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        // Use JWT authorities if available, otherwise fall back to UserDetails authorities
                        grantedAuthorities.isEmpty() ? userDetails.getAuthorities() : grantedAuthorities
                );

                // Set additional authentication details
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set authentication in Spring Security context
                SecurityContextHolder.getContext().setAuthentication(authToken);

                logger.debug("Authentication set in SecurityContext for user: {}", userEmail);
            } else {
                logger.debug("JWT token is invalid for user: {}", userEmail);
            }
        } else {
            logger.debug("No email extracted or authentication already exists.");
        }
    }

    /**
     * Optional: Override this method if you want to disable the filter for specific requests
     * based on more complex logic
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // You can add custom logic here to determine if the filter should not run
        // for specific requests. By default, it runs for all requests.
        return false;
    }
}
