package com.doruk.service;

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.annotation.Value;
import io.micronaut.scheduling.annotation.Scheduled;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;

/**
 * Scheduled task for automatic key rotation.
 */
@Singleton
@Requires(property = "jwk.rotation.enabled", value = "true", defaultValue = "true")
public class KeyRotationScheduler {

    private static final Logger LOG = LoggerFactory.getLogger(KeyRotationScheduler.class);

    private final KeyStorageService keyStorageService;
    private final boolean rotationEnabled;
    private final long rotationIntervalMinutes;

    private Instant lastRotation = Instant.now();
    private int rotationCount = 0;

    public KeyRotationScheduler(
            KeyStorageService keyStorageService,
            @Value("${jwk.rotation.enabled:true}") boolean rotationEnabled,
            @Value("${jwk.rotation.interval-minutes:20}") long rotationIntervalMinutes) {
        this.keyStorageService = keyStorageService;
        this.rotationEnabled = rotationEnabled;
        this.rotationIntervalMinutes = rotationIntervalMinutes;

        LOG.info("Key rotation scheduler initialized");
        LOG.info("Rotation enabled: {}", rotationEnabled);
        LOG.info("Rotation interval: {} minutes", rotationIntervalMinutes);
    }

    @Scheduled(fixedDelay = "${jwk.rotation.interval-minutes:20}m",
            initialDelay = "${jwk.rotation.initial-delay-minutes:20}m")
    public void rotateKeys() {
        if (!rotationEnabled) {
            return;
        }

        try {
            LOG.info("=== Starting scheduled key rotation #{} ===", rotationCount + 1);

            keyStorageService.rotateKeys();

            lastRotation = Instant.now();
            rotationCount++;

            LOG.info("=== Key rotation completed successfully ===");

        } catch (Exception e) {
            LOG.error("Key rotation failed!", e);
        }
    }

    public boolean triggerManualRotation() {
        LOG.warn("Manual key rotation triggered");
        try {
            keyStorageService.rotateKeys();
            lastRotation = Instant.now();
            rotationCount++;
            LOG.info("Manual key rotation completed successfully");
            return true;
        } catch (Exception e) {
            LOG.error("Manual key rotation failed", e);
            return false;
        }
    }

    public RotationStats getStats() {
        Duration elapsed = Duration.between(lastRotation, Instant.now());
        Duration remaining = Duration.ofMinutes(rotationIntervalMinutes).minus(elapsed);
        if (remaining.isNegative()) {
            remaining = Duration.ZERO;
        }

        return new RotationStats(
                rotationCount,
                lastRotation,
                remaining,
                rotationEnabled
        );
    }

    public record RotationStats(
            int totalRotations,
            Instant lastRotation,
            Duration timeUntilNext,
            boolean enabled
    ) {}
}