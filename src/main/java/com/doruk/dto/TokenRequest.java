package com.doruk.dto;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO for token generation.
 * Contains the subject (username or identifier) for which to generate a JWT token.
 */
@Introspected
@Serdeable
public class TokenRequest {

    @NotBlank
    private String subject;

    public TokenRequest() {
    }

    public TokenRequest(String subject) {
        this.subject = subject;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }
}