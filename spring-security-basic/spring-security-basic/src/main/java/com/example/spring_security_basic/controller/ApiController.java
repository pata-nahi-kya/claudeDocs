package com.example.spring_security_basic.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * REST API Controller
 * 
 * This controller demonstrates how to secure REST endpoints using Spring Security.
 * It provides JSON responses instead of HTML views.
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    /**
     * Public API endpoint - accessible to everyone
     * 
     * @return public information as JSON
     */
    @GetMapping("/public")
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a public endpoint");
        response.put("timestamp", System.currentTimeMillis());
        response.put("access", "No authentication required");
        
        return ResponseEntity.ok(response);
    }

    /**
     * User API endpoint - requires authentication
     * 
     * @return user information as JSON
     */
    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> userEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Welcome to user API endpoint");
        response.put("username", auth.getName());
        response.put("roles", auth.getAuthorities());
        response.put("timestamp", System.currentTimeMillis());
        response.put("access", "USER role required");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Management API endpoint - requires MANAGER or ADMIN role
     * 
     * @return management information as JSON
     */
    @GetMapping("/management")
    public ResponseEntity<Map<String, Object>> managementEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Welcome to management API endpoint");
        response.put("username", auth.getName());
        response.put("roles", auth.getAuthorities());
        response.put("timestamp", System.currentTimeMillis());
        response.put("access", "MANAGER or ADMIN role required");
        
        // Add some management-specific data
        response.put("managementInfo", Map.of(
            "totalUsers", 150,
            "activeUsers", 45,
            "systemStatus", "Operational"
        ));
        
        return ResponseEntity.ok(response);
    }

    /**
     * Admin API endpoint - requires ADMIN role only
     * 
     * @return admin information as JSON
     */
    @GetMapping("/admin")
    public ResponseEntity<Map<String, Object>> adminEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Welcome to admin API endpoint");
        response.put("username", auth.getName());
        response.put("roles", auth.getAuthorities());
        response.put("timestamp", System.currentTimeMillis());
        response.put("access", "ADMIN role required");
        
        // Add some admin-specific data
        response.put("adminInfo", Map.of(
            "systemHealth", "Good",
            "lastBackup", "2024-01-15 02:00:00",
            "serverUptime", "15 days, 3 hours",
            "memoryUsage", "45%"
        ));
        
        return ResponseEntity.ok(response);
    }

    /**
     * Current user information endpoint
     * 
     * @return current authenticated user details as JSON
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (auth == null || !auth.isAuthenticated()) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "User not authenticated");
            return ResponseEntity.status(401).body(response);
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("username", auth.getName());
        response.put("roles", auth.getAuthorities());
        response.put("authenticated", auth.isAuthenticated());
        response.put("authType", auth.getClass().getSimpleName());
        
        return ResponseEntity.ok(response);
    }
}
