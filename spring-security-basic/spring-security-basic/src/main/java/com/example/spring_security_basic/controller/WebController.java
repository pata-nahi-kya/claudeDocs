package com.example.spring_security_basic.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Main Web Controller
 * 
 * This controller handles the main web pages and routes for the application.
 * It demonstrates different security access levels and user authentication.
 */
@Controller
public class WebController {

    /**
     * Home page - accessible to everyone
     * 
     * @param model Spring Model for passing data to the view
     * @return home template name
     */
    @GetMapping("/")
    public String home(Model model) {
        // Get current authentication info
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        // Check if user is authenticated (not anonymous)
        if (auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser")) {
            model.addAttribute("username", auth.getName());
            model.addAttribute("roles", auth.getAuthorities());
            model.addAttribute("isAuthenticated", true);
        } else {
            model.addAttribute("isAuthenticated", false);
        }
        
        model.addAttribute("pageTitle", "Welcome to Spring Security Demo");
        return "home";
    }

    /**
     * Alternative home mapping
     */
    @GetMapping("/home")
    public String homeAlternative(Model model) {
        return home(model);
    }

    /**
     * Login page
     * 
     * @param error indicates if there was a login error
     * @param logout indicates if user just logged out
     * @param model Spring Model for passing data to the view
     * @return login template name
     */
    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                       @RequestParam(value = "logout", required = false) String logout,
                       Model model) {
        
        if (error != null) {
            model.addAttribute("errorMessage", "Invalid username or password!");
        }
        
        if (logout != null) {
            model.addAttribute("logoutMessage", "You have been logged out successfully!");
        }
        
        model.addAttribute("pageTitle", "Login");
        return "login";
    }

    /**
     * Dashboard - accessible to authenticated users only
     * 
     * @param model Spring Model for passing data to the view
     * @return dashboard template name
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        model.addAttribute("username", auth.getName());
        model.addAttribute("roles", auth.getAuthorities());
        model.addAttribute("pageTitle", "User Dashboard");
        
        return "dashboard";
    }

    /**
     * User area - accessible to users with USER role
     * 
     * @param model Spring Model for passing data to the view
     * @return user template name
     */
    @GetMapping("/user")
    public String userArea(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        model.addAttribute("username", auth.getName());
        model.addAttribute("pageTitle", "User Area");
        model.addAttribute("message", "Welcome to the user area! Only authenticated users with USER role can access this page.");
        
        return "user";
    }

    /**
     * Management area - accessible to MANAGER and ADMIN roles
     * 
     * @param model Spring Model for passing data to the view
     * @return management template name
     */
    @GetMapping("/management")
    public String managementArea(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        model.addAttribute("username", auth.getName());
        model.addAttribute("roles", auth.getAuthorities());
        model.addAttribute("pageTitle", "Management Area");
        model.addAttribute("message", "Welcome to the management area! Only managers and admins can access this page.");
        
        return "management";
    }

    /**
     * Admin area - accessible to ADMIN role only
     * 
     * @param model Spring Model for passing data to the view
     * @return admin template name
     */
    @GetMapping("/admin")
    public String adminArea(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        model.addAttribute("username", auth.getName());
        model.addAttribute("roles", auth.getAuthorities());
        model.addAttribute("pageTitle", "Admin Area");
        model.addAttribute("message", "Welcome to the admin area! Only administrators can access this page.");
        
        return "admin";
    }

    /**
     * Access denied page
     * 
     * @param model Spring Model for passing data to the view
     * @return access-denied template name
     */
    @GetMapping("/access-denied")
    public String accessDenied(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (auth != null) {
            model.addAttribute("username", auth.getName());
            model.addAttribute("roles", auth.getAuthorities());
        }
        
        model.addAttribute("pageTitle", "Access Denied");
        model.addAttribute("errorMessage", "You don't have permission to access this resource.");
        
        return "access-denied";
    }
}
