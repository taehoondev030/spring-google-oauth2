package com.example.demo.auth.oauth2;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
public class OAuth2UserPrincipal implements OAuth2User {

    private final Long userId;
    private final String role;
    private final String providerId;
    private final String email;

    private final Map<String, Object> attributes;
    private final Collection<? extends GrantedAuthority> authorities;

    public OAuth2UserPrincipal(
            Long userId,
            String role,
            String providerId,
            String email,
            Map<String, Object> attributes
    ) {
        this.userId = userId;
        this.role = role;
        this.providerId = providerId;
        this.email = email;
        this.attributes = attributes;
        this.authorities = List.of(new SimpleGrantedAuthority(role));
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getName() {
        return String.valueOf(userId);
    }
}
