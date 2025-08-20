package com.uni_gate.auth_service.service.impl;

import com.uni_gate.auth_service.entity.User;
import com.uni_gate.auth_service.service.JwtService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private static final String KID = "auth-service-key";
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    @Override
    public String extractUsername(String token) {
        return Jwts
                .parser()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    @Override
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        if (userDetails instanceof User user) {
            extraClaims.put("role", user.getRole());
        }

        return Jwts.builder()
                .setHeaderParam("kid", KID)
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        Date exp = Jwts.parser()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody().getExpiration();
        return exp.before(new Date());
    }
}
