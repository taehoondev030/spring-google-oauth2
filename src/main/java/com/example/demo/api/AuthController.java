package com.example.demo.api;

import com.example.demo.auth.jwt.JwtUtil;
import com.example.demo.auth.token.TokenHash;
import com.example.demo.auth.token.domain.RefreshToken;
import com.example.demo.auth.token.repository.RefreshTokenRepository;
import com.example.demo.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Value("${jwt.refresh-expire-ms}")
    private long refreshExpireMs;

    @Getter
    static class RefreshRequest {
        private String refreshToken;
    }

    @Getter
    static class TokenResponse {
        private final String accessToken;
        private final String refreshToken;

        TokenResponse(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestBody RefreshRequest req) {

        String rawRefresh = req.getRefreshToken();
        if (rawRefresh == null || rawRefresh.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        // 1) JWT 자체 유효성(서명/만료)
        if (!jwtUtil.isValid(rawRefresh)) {
            return ResponseEntity.status(401).build();
        }

        Claims claims = jwtUtil.parseClaims(rawRefresh);
        Long userId = Long.valueOf(claims.getSubject());
        String role = (String) claims.get("role");

        // 2) DB에 저장된 refresh인지 확인(해시로)
        String hash = TokenHash.sha256(rawRefresh);

        RefreshToken saved = refreshTokenRepository.findByTokenHash(hash)
                .orElse(null);

        if (saved == null) {
            // 이미 회전되어 폐기된 토큰이거나(재사용), DB에 없는 토큰(위조)
            return ResponseEntity.status(401).build();
        }

        if (saved.isExpired() || saved.isRevoked()) {
            return ResponseEntity.status(401).build();
        }

        // 3) 새 토큰 발급 (Rotation)
        String newAccess = jwtUtil.createAccessToken(userId, role);
        String newRefresh = jwtUtil.createRefreshToken(userId, role);

        String newHash = TokenHash.sha256(newRefresh);
        LocalDateTime newExpires = LocalDateTime.now().plusSeconds(refreshExpireMs / 1000);

        saved.rotateTo(newHash, newExpires);
        refreshTokenRepository.save(saved);

        return ResponseEntity.ok(new TokenResponse(newAccess, newRefresh));
    }
}