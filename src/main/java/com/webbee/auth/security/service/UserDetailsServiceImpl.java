package com.webbee.auth.security.service;

import com.webbee.auth.entity.Role;
import com.webbee.auth.repository.UserRepository;
import com.webbee.auth.security.model.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

/**
 * Реализация интерфейса UserDetailsService для загрузки пользовательских данных
 * Отвечает за загрузку информации о пользователе по его имени пользователя
 * и преобразование данных из сущности базы данных в объект.
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .map(user -> new CustomUserDetails(
                                user.getUsername(),
                                user.getPassword(),
                                user.getRoles().stream()
                                        .map(Role::getName)
                                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                        .collect(Collectors.toSet()),
                                user.getEmail()
                        )
                ).orElseThrow(() -> new UsernameNotFoundException("Cant find user with name"));
    }

}
