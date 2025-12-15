package com.doruk.dto;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;

import java.util.List;

/**
 * Request DTO for token generation.
 * Contains the subject (username or identifier) for which to generate a JWT token.
 */
@Introspected
@Serdeable
public class TokenRequest {
    @NotBlank
    private String aud;

    @NotBlank
    private String sub;

    @Nullable
    private List<Integer> scp;

    public TokenRequest(String sub, String aud, List<Integer> scp) {
        this.sub = sub;
        this.aud = aud;
        this.scp = scp;
    }

    public String getSubject() {
        return sub;
    }

    public String getAudience() {
        return aud;
    }

    public List<Integer> getScopes() {
        return scp;
    }
}