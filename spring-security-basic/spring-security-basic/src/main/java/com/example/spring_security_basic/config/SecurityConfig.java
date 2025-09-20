package com.example.springsecuritybasic.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security Configuration Class
 * 
 * This class configures Spring Security for the application.
 * It defines authentication, authorization, and other security settings.
 */
@Configuration
@EnableWebSecurity // Enables Spring Security's web security support
public class SecurityConfig {

    /**
     * Password Encoder Bean
     * 
     * BCryptPasswordEncoder is a strong hashing function designed for passwords.
     * It's recommended over plain text or weaker hashing algorithms.
     * 
     * @return BCryptPasswordEncoder instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * User Details Service Bean
     * 
     * This creates an in-memory user store for demonstration purposes.
     * In production, you would typically use a database-backed user store.
     * 
     * @return UserDetailsService with predefined users
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // Create admin user with ADMIN and USER roles
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin123"))
                .roles("ADMIN", "USER") // Roles are prefixed with "ROLE_" internally
                .build();

        // Create regular user with USER role only
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("user123"))
                .roles("USER")
                .build();

        // Create manager user with MANAGER and USER roles
        UserDetails manager = User.builder()
                .username("manager")
                .password(passwordEncoder().encode("manager123"))
                .roles("MANAGER", "USER")
                .build();

        // Return in-memory user details manager with all users
        return new InMemoryUserDetailsManager(admin, user, manager);
    }

    /**
     * Security Filter Chain Configuration
     * 
     * This method configures the security filter chain, defining:
     * - Which URLs require authentication
     * - Role-based access control
     * - Login/logout behavior
     * - CSRF settings
     * 
     * @param http HttpSecurity object to configure
     * @return SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Configure authorization rules
            .authorizeHttpRequests(authz -> authz
                // Public endpoints - no authentication required
                .requestMatchers("/", "/home", "/public/**", "/css/**", "/js/**", "/images/**").permitAll()
                
                // Admin-only endpoints
                .requestMatchers("/admin/**").hasRole("ADMIN")
                
                // Manager and Admin can access management endpoints
                .requestMatchers("/management/**").hasAnyRole("MANAGER", "ADMIN")
                
                // User endpoints - accessible by any authenticated user
                .requestMatchers("/user/**").hasRole("USER")
                
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            // Configure form-based login
            .formLogin(form -> form
                .loginPage("/login") // Custom login page URL
                .loginProcessingUrl("/perform_login") // URL to submit login form
                .defaultSuccessUrl("/dashboard", true) // Redirect after successful login
                .failureUrl("/login?error=true") // Redirect after failed login
                .usernameParameter("username") // Username field name
                .passwordParameter("password") // Password field name
                .permitAll() // Allow everyone to see login page
            )
            // Configure logout
            .logout(logout -> logout
                .logoutUrl("/logout") // URL to trigger logout
                .logoutSuccessUrl("/login?logout=true") // Redirect after logout
                .invalidateHttpSession(true) // Invalidate session
                .deleteCookies("JSESSIONID") // Delete session cookies
                .permitAll()
            )
            // Configure session management
            .sessionManagement(session -> session
                .maximumSessions(1) // Allow only one session per user
                .maxSessionsPreventsLogin(false) // Don't prevent login, invalidate old session
            )
            // Configure remember-me functionality
            .rememberMe(remember -> remember
                .key("uniqueAndSecret") // Secret key for remember-me token
                .tokenValiditySeconds(86400) // Token valid for 24 hours
                .userDetailsService(userDetailsService()) // User details service for remember-me
            )
            // Exception handling
            .exceptionHandling(ex -> ex
                .accessDeniedPage("/access-denied") // Custom access denied page
            );

        return http.build();
    }
}