package com.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String loginPage() {
        System.out.println("login");
        return "login";
    }

    @GetMapping("/courses")
    public String getCourses() {
        return "courses";
    }
}
