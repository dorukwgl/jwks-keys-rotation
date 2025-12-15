package com.doruk.service;

import com.doruk.dto.ActiveKeys;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import io.micronaut.context.annotation.Value;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

/**
 * Service for managing key storage and generation.
 * Handles file-based persistence of primary and secondary keys.
 */
@Singleton
public class KeyStorageService {

    private static final Logger LOG = LoggerFactory.getLogger(KeyStorageService.class);

    private final Path keysDirectory;
    private final Path primaryKeyPath;
    private final Path secondaryKeyPath;

    private volatile ActiveKeys activeKeys;

    public KeyStorageService(@Value("${jwk.storage.directory:./keys}") String keysDirectory) {
        this.keysDirectory = Paths.get(keysDirectory);
        this.primaryKeyPath = this.keysDirectory.resolve("primary.jwk");
        this.secondaryKeyPath = this.keysDirectory.resolve("secondary.jwk");

        initialize();
    }

    private void initialize() {
        try {
            // Create directory if needed
            if (!Files.exists(keysDirectory)) {
                Files.createDirectories(keysDirectory);
                LOG.info("Created keys directory: {}", keysDirectory);
            }

            // Load or generate keys
            if (!Files.exists(primaryKeyPath) || !Files.exists(secondaryKeyPath)) {
                LOG.info("Keys not found. Generating new key pair...");
                generateInitialKeys();
            } else {
                loadKeys();
            }
        } catch (Exception e) {
            LOG.error("Failed to initialize key storage", e);
            throw new RuntimeException("Key storage initialization failed", e);
        }
    }

    private void generateInitialKeys() throws JOSEException, IOException {
        LOG.info("Generating initial EC P-256 key pair...");

        var primaryKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("d-key-" + UUID.randomUUID().toString().substring(0, 8))
                .algorithm(com.nimbusds.jose.JWSAlgorithm.ES256)
                .generate();

        var secondaryKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("d-key-" + UUID.randomUUID().toString().substring(0, 8))
                .algorithm(com.nimbusds.jose.JWSAlgorithm.ES256)
                .generate();
        activeKeys = new ActiveKeys(primaryKey, secondaryKey);
        saveKeys();

        LOG.info("Successfully generated and stored initial keys");
        LOG.info("Primary key ID: {}", primaryKey.getKeyID());
        LOG.info("Secondary key ID: {}", secondaryKey.getKeyID());
    }

    private void loadKeys() throws Exception {
        String primaryJson = Files.readString(primaryKeyPath);
        String secondaryJson = Files.readString(secondaryKeyPath);

        var primaryKey = ECKey.parse(primaryJson);
        var secondaryKey = ECKey.parse(secondaryJson);
        activeKeys = new ActiveKeys(primaryKey, secondaryKey);

        LOG.info("Loaded existing keys from storage");
        LOG.info("Primary key ID: {}", primaryKey.getKeyID());
        LOG.info("Secondary key ID: {}", secondaryKey.getKeyID());
    }

    private void saveKeys() throws IOException {
        Files.writeString(primaryKeyPath, activeKeys.primary().toJSONString(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        Files.writeString(secondaryKeyPath, activeKeys.secondary().toJSONString(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        // Set restrictive permissions on Unix-like systems
        try {
            Files.setPosixFilePermissions(primaryKeyPath,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            Files.setPosixFilePermissions(secondaryKeyPath,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException e) {
            // Windows doesn't support POSIX permissions
            LOG.debug("Cannot set POSIX permissions on this platform");
        }
    }

    public synchronized void rotateKeys() throws JOSEException, IOException {
        LOG.info("Starting key rotation...");

        // Generate new primary
        var newPrimaryKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("d-key-" + UUID.randomUUID().toString().substring(0, 8))
                .algorithm(com.nimbusds.jose.JWSAlgorithm.ES256)
                .generate();
        var newSecondary = activeKeys.primary();

        activeKeys = new ActiveKeys(newPrimaryKey, newSecondary);

        // Save to disk
        saveKeys();

        LOG.info("Key rotation completed successfully");
        LOG.info("New primary key ID: {}", activeKeys.primary().getKeyID());
    }

    public ECKey getPrimaryKey() {
        return activeKeys.primary();
    }

    public ECKey getSecondaryKey() {
        return activeKeys.secondary();
    }

    public Path getKeysDirectory() {
        return keysDirectory;
    }
}