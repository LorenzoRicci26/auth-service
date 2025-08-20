package com.uni_gate.auth_service.config;

import com.uni_gate.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
@RequiredArgsConstructor
public class AppConfig {

    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username).orElseThrow(
                () -> new UsernameNotFoundException("User not found")
        );
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public KeyPair rsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static String loadKey(String path) throws IOException {
        return Files.readString(Path.of(path))
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s", "");
    }

    @Bean
    public RSAPrivateKey rsaPrivateKey() throws IOException, GeneralSecurityException {
        String key = loadKey("src/main/resources/keys/private.pem");
        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(keySpec);
    }

    @Bean
    public RSAPublicKey rsaPublicKey() throws IOException, GeneralSecurityException {
        String key = loadKey("src/main/resources/keys/public.pem");
        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(keySpec);
    }
}
