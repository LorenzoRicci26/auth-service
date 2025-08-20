package com.uni_gate.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class AuthResponseDto {
    private String userId;
    private String email;
    private String role;
    private String message;
}
