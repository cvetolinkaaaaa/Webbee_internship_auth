package com.webbee.auth;

import com.webbee.auth.entity.AuthType;
import com.webbee.auth.entity.Role;
import com.webbee.auth.entity.User;
import com.webbee.auth.repository.RoleRepository;
import com.webbee.auth.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class DataInit {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    @PostConstruct
    void init() {
        Optional<Role> role = roleRepository.findByName("ADMIN");
        Optional<User> user = userRepository.findByUsername("ADMIN");
        if (user.isPresent()) {
            return;
        }
        if (role.isPresent()) {
            Role rl = role.get();
            Set<Role> roles = new HashSet<>();
            roles.add(rl);
            User admin = User.builder()
                    .username("ADMIN")
                    .password(passwordEncoder.encode("password123"))
                    .email("admin@yandex.ru")
                    .roles(roles)
                    .authType(AuthType.LOCAL)
                    .build();
            userRepository.save(admin);
        }
    }
}