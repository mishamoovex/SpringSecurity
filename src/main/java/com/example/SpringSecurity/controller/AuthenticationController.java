package com.example.SpringSecurity.controller;

import com.example.SpringSecurity.config.JwtUtils;
import com.example.SpringSecurity.dto.AuthenticationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtils jwtUtils;

    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticate(
            @RequestBody AuthenticationRequest request
    ){
        Authentication auth = new UsernamePasswordAuthenticationToken(
                request.getEmail(),request.getPassword()
        );
        authManager.authenticate(auth);

        final UserDetails user = userDetailsService.loadUserByUsername(request.getEmail());

        if (user != null){
            return ResponseEntity.ok( jwtUtils.generateToken(user));
        }else {
            return ResponseEntity.status(400).body("Some error occurred");
        }
    }
}
