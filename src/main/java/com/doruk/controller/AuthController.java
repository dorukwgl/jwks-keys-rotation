package com.doruk.controller;

import com.doruk.dto.TokenRequest;
import com.doruk.dto.TokenResponse;
import com.doruk.service.JwtService;
import io.micronaut.context.annotation.Value;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authentication controller for JWT token generation.
 */
@Controller("/auth")
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    private final JwtService jwtService;
    private final long tokenExpiryMinutes;

    public AuthController(JwtService jwtService,
                          @Value("${jwt.token.expiry-minutes:10}") long tokenExpiryMinutes) {
        this.jwtService = jwtService;
        this.tokenExpiryMinutes = tokenExpiryMinutes;
    }

    /**
     * Generate a JWT token for the given subject.
     *
     * POST /auth/token
     * Body: {"subject": "username"}
     */
    @Post("/token")
    public HttpResponse<TokenResponse> generateToken(@Valid @Body TokenRequest request) {
        LOG.debug("Generating token for subject: {}", request.getSubject());

        try {
            String token = jwtService.generateToken(request.getSubject());

            TokenResponse response = new TokenResponse(token, tokenExpiryMinutes * 60);
            return HttpResponse.ok(response);

        } catch (Exception e) {
            LOG.error("Failed to generate token", e);
            return HttpResponse.serverError();
        }
    }
}