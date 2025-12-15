package com.doruk.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.Value;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

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
    public String generateToken(String subject) {
        try {
            ECKey primaryKey = keyStorageService.getPrimaryKey();

            // Create JWT claims
            Date now = new Date();
            Date expiry = new Date(now.getTime() + (tokenExpiryMinutes * 60 * 1000));

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issueTime(now)
                    .expirationTime(expiry)
                    .build();

            // Create JWT header with key ID
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(primaryKey.getKeyID())
                    .build();

            // Create signed JWT
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);

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