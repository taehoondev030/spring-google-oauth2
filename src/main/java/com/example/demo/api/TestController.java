package com.example.demo.api;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/health")
    public String health() {
        return "OK";
    }

    @GetMapping("/api/me")
    public Object me(Authentication authentication) {
        return authentication;
    }
}
