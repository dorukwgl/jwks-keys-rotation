package com.doruk.controller;

import com.doruk.service.KeyStorageService;
import com.nimbusds.jose.jwk.ECKey;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JWKS (JSON Web Key Set) endpoint controller.
 * Exposes public keys for JWT validation.
 */
@Controller("/.well-known")
public class JwksController {

    private static final Logger LOG = LoggerFactory.getLogger(JwksController.class);

    private final KeyStorageService keyStorageService;

    public JwksController(KeyStorageService keyStorageService) {
        this.keyStorageService = keyStorageService;
    }

    /**
     * Get JWKS (JSON Web Key Set) containing public keys.
     *
     * GET /.well-known/jwks.json
     *
     * Returns both primary and secondary public keys for token validation.
     */
    @Get("/jwks.json")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> getJwks() {
        LOG.debug("JWKS endpoint called");

        try {
            ECKey primaryKey = keyStorageService.getPrimaryKey();
            ECKey secondaryKey = keyStorageService.getSecondaryKey();

            // Convert to public keys only (remove private key material)
            Map<String, Object> primaryPublic = primaryKey.toPublicJWK().toJSONObject();
            Map<String, Object> secondaryPublic = secondaryKey.toPublicJWK().toJSONObject();

            Map<String, Object> jwks = new HashMap<>();
            jwks.put("keys", List.of(primaryPublic, secondaryPublic));

            return jwks;

        } catch (Exception e) {
            LOG.error("Failed to generate JWKS", e);
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Failed to retrieve keys");
            return error;
        }
    }
}