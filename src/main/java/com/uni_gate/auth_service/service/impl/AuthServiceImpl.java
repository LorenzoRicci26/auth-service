package com.uni_gate.auth_service.service.impl;

import com.uni_gate.auth_service.dto.AuthResponseDto;
import com.uni_gate.auth_service.dto.LoginDto;
import com.uni_gate.auth_service.dto.RegistrationDto;
import com.uni_gate.auth_service.entity.Role;
import com.uni_gate.auth_service.entity.User;
import com.uni_gate.auth_service.exception.EmailAlreadyExistsException;
import com.uni_gate.auth_service.repository.UserRepository;
import com.uni_gate.auth_service.service.AuthService;
import com.uni_gate.auth_service.service.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public AuthResponseDto register(RegistrationDto request, HttpServletResponse response) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new EmailAlreadyExistsException(request.getEmail());
        }
        var user = User.builder()
                .id(UUID.randomUUID().toString())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.valueOf(request.getRole().name()))
                .build();

        User savedUser = userRepository.save(user);

        var jwtToken = jwtService.generateToken(user);
        Cookie cookie = new Cookie("authToken", jwtToken);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(3600);
        cookie.setAttribute("SameSite", "Strict");

        response.addCookie(cookie);

        return AuthResponseDto.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .role(savedUser.getRole().name())
                .message("User registered successfully!")
                .build();
    }

    @Override
    public AuthResponseDto login(LoginDto request, HttpServletResponse response) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        Cookie cookie = new Cookie("authToken", jwtToken);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(3600);

        response.addCookie(cookie);

        return AuthResponseDto.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .role(user.getRole().name())
                .message("Login successful")
                .build();
    }
}
