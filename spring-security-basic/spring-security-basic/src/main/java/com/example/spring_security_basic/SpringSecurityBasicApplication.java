package com.example.spring_security_basic;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main Application Class
 * 
 * @SpringBootApplication is a convenience annotation that adds:
 * - @Configuration: Tags the class as a source of bean definitions
 * - @EnableAutoConfiguration: Enables Spring Boot's auto-configuration mechanism
 * - @ComponentScan: Enables component scanning in the current package and sub-packages
 */
@SpringBootApplication
public class SpringSecurityBasicApplication {

    /**
     * Main method to start the Spring Boot application
     * 
     * @param args command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityBasicApplication.class, args);
        System.out.println("Spring Boot Security Application Started Successfully!");
        System.out.println("Access the application at: http://localhost:8080");
        System.out.println("Demo credentials:");
        System.out.println("Admin - Username: admin, Password: admin123");
        System.out.println("Manager - Username: manager, Password: manager123");
        System.out.println("User - Username: user, Password: user123");
    }
}
