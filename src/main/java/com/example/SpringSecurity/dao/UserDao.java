package com.example.SpringSecurity.dao;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Repository
public class UserDao {

    private final static List<UserDetails> APPLICATION_USERS = Arrays.asList(
            new User(
                    "mishamoovex@gmail.com",
                    "password",
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"))
            ),
            new User(
                    "user@gmail.com",
                    "password",
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
            )
    );

    public UserDetails findUserByEmail(String email) {
        return APPLICATION_USERS
                .stream()
                .filter(u -> Objects.equals(u.getUsername(), email))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("No user was found"));

    }
}
