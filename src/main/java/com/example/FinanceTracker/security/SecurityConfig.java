package com.example.FinanceTracker.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * Spring Security Configuration Class
 *
 * Features:
 * - JWT-based authentication
 * - Role-based access control (RBAC)
 * - CORS configuration
 * - Stateless session management
 * - Custom logout handling
 *
 * Usage:
 * 1. Update package name to match your project
 * 2. Modify WHITE_LIST_URL array for your public endpoints
 * 3. Adjust role-based access rules in securityFilterChain()
 * 4. Update CORS origins for your frontend application
 * 5. Ensure you have AuthenticationProvider, JwtAuthenticationFilter, and LogoutHandler beans
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final LogoutHandler logoutHandler;

    /**
     * Define public endpoints that don't require authentication
     * Customize this array based on your application's needs
     */
    private static final String[] WHITE_LIST_URL = {
            // Authentication endpoints
            "/api/auth/**",
            "/api/public/**",

            // Swagger/OpenAPI documentation endpoints
            "/v2/api-docs",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui/**",
            "/webjars/**",
            "/swagger-ui.html",

            // Error handling
            "/error"
    };

    /**
     * Main security filter chain configuration
     * Customize the authorization rules based on your application's requirements
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Enable CORS with custom configuration
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Disable CSRF for stateless JWT authentication
                .csrf(AbstractHttpConfigurer::disable)

                // Configure authorization rules
                .authorizeHttpRequests(req -> req
                        // Allow public endpoints without authentication
                        .requestMatchers(WHITE_LIST_URL).permitAll()

                        // Example role-based access control rules
                        // Customize these based on your application's roles and endpoints

                        // User profile endpoints
                        .requestMatchers(HttpMethod.GET, "/api/users/me").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/users").hasRole("ADMIN")

                        // Resource-specific permissions (example for task management system)
                        .requestMatchers(HttpMethod.GET, "/api/teams/**", "/api/projects/**", "/api/tasks/**")
                        .hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/teams/**", "/api/projects/**", "/api/tasks/**")
                        .hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/teams/**", "/api/projects/**", "/api/tasks/**")
                        .hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/teams/**", "/api/projects/**", "/api/tasks/**")
                        .hasRole("ADMIN")

                        // Management endpoints with fine-grained permissions
                        .requestMatchers("/api/management/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_MANAGER")
                        .requestMatchers(HttpMethod.GET, "/api/management/**")
                        .hasAnyRole("ADMIN_READ", "MANAGER_READ")
                        .requestMatchers(HttpMethod.POST, "/api/management/**")
                        .hasAnyRole("ADMIN_CREATE", "MANAGER_CREATE")
                        .requestMatchers(HttpMethod.PUT, "/api/management/**")
                        .hasAnyRole("ADMIN_UPDATE", "MANAGER_UPDATE")
                        .requestMatchers(HttpMethod.DELETE, "/api/management/**")
                        .hasAnyRole("ADMIN_DELETE", "MANAGER_DELETE")

                        // Require authentication for all other requests
                        .anyRequest().authenticated()
                )

                // Configure stateless session management for JWT
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Set custom authentication provider
                .authenticationProvider(authenticationProvider)

                // Add JWT filter before the standard username/password filter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

                // Configure logout functionality
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler((request, response, authentication) ->
                                SecurityContextHolder.clearContext())
                );

        return http.build();
    }

    /**
     * CORS configuration for cross-origin requests
     * Update the allowed origins to match your frontend application URLs
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Configure allowed origins (update these for your environment)
        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",    // React default
                "http://localhost:8080",    // Spring Boot default
                "http://localhost:8081",    // Custom frontend
                "https://yourdomain.com"    // Production domain
        ));

        // Configure allowed HTTP methods
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"
        ));

        // Configure allowed headers
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization", "Content-Type", "X-Requested-With", "Accept", "Origin"
        ));

        // Allow credentials (cookies, authorization headers, etc.)
        configuration.setAllowCredentials(true);

        // Apply CORS configuration to all endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
