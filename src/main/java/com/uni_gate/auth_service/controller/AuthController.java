package com.uni_gate.auth_service.controller;

import com.uni_gate.auth_service.dto.AuthResponseDto;
import com.uni_gate.auth_service.dto.LoginDto;
import com.uni_gate.auth_service.dto.RegistrationDto;
import com.uni_gate.auth_service.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final String KID = "auth-service-key";
    private final RSAPublicKey publicKey;
    private final AuthService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> register(@RequestBody RegistrationDto request, HttpServletResponse response) {
        log.info("Register user with email: {}", request.getEmail());
        return ResponseEntity.ok(authenticationService.register(request, response));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> authenticate(@RequestBody LoginDto request, HttpServletResponse response) {
        log.info("Authenticate user with email: {}", request.getEmail());
        return ResponseEntity.ok(authenticationService.login(request, response));
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> keys() {
        String modulus = Base64.getUrlEncoder()
                .encodeToString(publicKey.getModulus().toByteArray());
        String exponent = Base64.getUrlEncoder()
                .encodeToString(publicKey.getPublicExponent().toByteArray());
        Map<String,Object> jwk = new HashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("kid", KID);
        jwk.put("use", "sig");
        jwk.put("alg", "RS256");
        jwk.put("n", modulus);
        jwk.put("e", exponent);

        Map<String,Object> keys = new HashMap<>();
        keys.put("keys", List.of(jwk));
        return keys;
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("authToken", null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
        return ResponseEntity.noContent().build();
    }
}
