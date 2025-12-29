package com.example.demo.auth.oauth2;

import com.example.demo.auth.jwt.JwtUtil;
import com.example.demo.auth.token.TokenHash;
import com.example.demo.auth.token.domain.RefreshToken;
import com.example.demo.auth.token.repository.RefreshTokenRepository;
import com.example.demo.user.domain.AuthProvider;
import com.example.demo.user.domain.User;
import com.example.demo.user.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class OAuth2JsonSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();
    @Value("${jwt.refresh-expire-ms}") private long refreshExpireMs;

    @Getter
    @AllArgsConstructor
    static class TokenResponse {
        private String accessToken;
        private String refreshToken;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {
        Object principalObj = authentication.getPrincipal();

        Long userId;
        String role;

        // 1) 우리가 만든 Principal이면 그대로 사용
        if (principalObj instanceof OAuth2UserPrincipal principal) {
            userId = principal.getUserId();
            role = principal.getRole();
        }
        // 2) OIDC(DefaultOidcUser) 또는 일반 OAuth2User면 attributes에서 sub로 다시 조회
        else if (principalObj instanceof OAuth2User oAuth2User) {
            String providerId = (String) oAuth2User.getAttributes().get("sub");
            if (providerId == null) {
                throw new IllegalStateException("No 'sub' in OAuth2 attributes. Check scope includes 'openid'.");
            }

            User user = userRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, providerId)
                    .orElseThrow(() -> new IllegalStateException("User not found after OAuth2 login"));

            userId = user.getId();
            role = user.getRole();
        }
        else {
            throw new IllegalStateException("Unsupported principal type: " + principalObj.getClass());
        }

        String accessToken = jwtUtil.createAccessToken(userId, role);
        String refreshToken = jwtUtil.createRefreshToken(userId, role);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalStateException("User not found"));

        String tokenHash = TokenHash.sha256(refreshToken);

        RefreshToken entity = RefreshToken.builder()
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(LocalDateTime.now().plusNanos(refreshExpireMs * 1_000_000))
                .revoked(false)
                .build();

        refreshTokenRepository.save(entity);

        TokenResponse body = new TokenResponse(accessToken, refreshToken);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
