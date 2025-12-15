package com.doruk.service;

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
import java.time.Instant;
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
    private final Path metadataPath;

    private ECKey primaryKey;
    private ECKey secondaryKey;

    public KeyStorageService(@Value("${jwk.storage.directory:./keys}") String keysDirectory) {
        this.keysDirectory = Paths.get(keysDirectory);
        this.primaryKeyPath = this.keysDirectory.resolve("primary.jwk");
        this.secondaryKeyPath = this.keysDirectory.resolve("secondary.jwk");
        this.metadataPath = this.keysDirectory.resolve("metadata.json");

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

        primaryKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("primary-" + UUID.randomUUID().toString().substring(0, 8))
                .algorithm(com.nimbusds.jose.JWSAlgorithm.ES256)
                .generate();

        secondaryKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("secondary-" + UUID.randomUUID().toString().substring(0, 8))
                .algorithm(com.nimbusds.jose.JWSAlgorithm.ES256)
                .generate();

        saveKeys();

        LOG.info("Successfully generated and stored initial keys");
        LOG.info("Primary key ID: {}", primaryKey.getKeyID());
        LOG.info("Secondary key ID: {}", secondaryKey.getKeyID());
    }

    private void loadKeys() throws Exception {
        String primaryJson = Files.readString(primaryKeyPath);
        String secondaryJson = Files.readString(secondaryKeyPath);

        primaryKey = ECKey.parse(primaryJson);
        secondaryKey = ECKey.parse(secondaryJson);

        LOG.info("Loaded existing keys from storage");
        LOG.info("Primary key ID: {}", primaryKey.getKeyID());
        LOG.info("Secondary key ID: {}", secondaryKey.getKeyID());
    }

    private void saveKeys() throws IOException {
        Files.writeString(primaryKeyPath, primaryKey.toJSONString(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        Files.writeString(secondaryKeyPath, secondaryKey.toJSONString(),
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

        // Move primary to secondary
        secondaryKey = primaryKey;

        // Generate new primary
        primaryKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("primary-" + UUID.randomUUID().toString().substring(0, 8))
                .algorithm(com.nimbusds.jose.JWSAlgorithm.ES256)
                .generate();

        // Save to disk
        saveKeys();
        updateMetadata();

        LOG.info("Key rotation completed successfully");
        LOG.info("New primary key ID: {}", primaryKey.getKeyID());
    }

    private void updateMetadata() throws IOException {
        String metadata = String.format(
                "{\"lastRotation\":\"%s\"}",
                Instant.now()
        );
        Files.writeString(metadataPath, metadata,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    public ECKey getPrimaryKey() {
        return primaryKey;
    }

    public ECKey getSecondaryKey() {
        return secondaryKey;
    }

    public Path getKeysDirectory() {
        return keysDirectory;
    }
}