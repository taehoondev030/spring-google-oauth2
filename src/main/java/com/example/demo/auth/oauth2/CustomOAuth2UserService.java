package com.example.demo.auth.oauth2;

import com.example.demo.user.domain.AuthProvider;
import com.example.demo.user.domain.User;
import com.example.demo.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Transactional
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String providerId = (String) oAuth2User.getAttributes().get("sub");
        String email = (String) oAuth2User.getAttributes().get("email");
        String name = (String) oAuth2User.getAttributes().get("name");
        String picture = (String) oAuth2User.getAttributes().get("picture");

        if (providerId == null) {
            throw new IllegalStateException("Google OAuth2 response does not contain 'sub'. Check scopes include 'openid'.");
        }
        if (email == null) {
            throw new IllegalStateException("Google OAuth2 response does not contain 'email'. Check scopes include 'email'.");
        }

        User user = userRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, providerId)
                .orElseGet(() -> userRepository.save(
                        User.builder()
                                .provider(AuthProvider.GOOGLE)
                                .providerId(providerId)
                                .email(email)
                                .name(name)
                                .picture(picture)
                                .role("ROLE_USER")
                                .build()
                ));

        return new OAuth2UserPrincipal(
                user.getId(),
                user.getRole(),
                providerId,
                email,
                oAuth2User.getAttributes()
        );
    }
}

