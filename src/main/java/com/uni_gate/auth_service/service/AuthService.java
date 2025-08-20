package com.uni_gate.auth_service.service;

import com.uni_gate.auth_service.dto.AuthResponseDto;
import com.uni_gate.auth_service.dto.LoginDto;
import com.uni_gate.auth_service.dto.RegistrationDto;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthService {
    AuthResponseDto register(RegistrationDto request, HttpServletResponse response);
    AuthResponseDto login(LoginDto request, HttpServletResponse response);
}

