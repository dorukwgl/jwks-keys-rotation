package com.doruk.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.Value;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Simple JWT service for signing and validating tokens.
 * Uses ES256 (ECDSA with P-256 curve) for signing.
 */
@Singleton
public class JwtService {

    private static final Logger LOG = LoggerFactory.getLogger(JwtService.class);

    private final KeyStorageService keyStorageService;
    private final long tokenExpiryMinutes;

    public JwtService(KeyStorageService keyStorageService,
                      @Value("${jwt.token.expiry-minutes:10}") long tokenExpiryMinutes) {
        this.keyStorageService = keyStorageService;
        this.tokenExpiryMinutes = tokenExpiryMinutes;
    }

    /**
     * Generate a signed JWT token for the given subject.
     *
     * @param subject the subject (username/identifier)
     * @return signed JWT as string
     */
    public String generateToken(String subject, String audience, List<Integer> scopes) {
        try {
            ECKey primaryKey = keyStorageService.getPrimaryKey();

            // Create JWT claims
            Instant now = Instant.now();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer("com.doruk.jwks")
                    .audience(audience)
                    .issueTime(Date.from(now))
                    .claim("scp", scopes)
                    .expirationTime(Date.from(now.plusSeconds(tokenExpiryMinutes * 60)))
                    .build();

            // Create JWT header with key ID
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(primaryKey.getKeyID())
                    .build();

            // Create signed JWT
            SignedJWT signedJWT = new SignedJWT(header, claims);

            // Sign with primary key
            JWSSigner signer = new ECDSASigner(primaryKey);
            signedJWT.sign(signer);

            String token = signedJWT.serialize();
            LOG.debug("Generated token for subject: {} with key ID: {}", subject, primaryKey.getKeyID());

            return token;

        } catch (Exception e) {
            LOG.error("Failed to generate token", e);
            throw new RuntimeException("Token generation failed", e);
        }
    }
}