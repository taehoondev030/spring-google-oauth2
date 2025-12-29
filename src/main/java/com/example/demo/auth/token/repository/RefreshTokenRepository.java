package com.example.demo.auth.token.repository;

import com.example.demo.auth.token.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken,String> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);
}
