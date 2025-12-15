package com.doruk.controller;

import com.doruk.service.KeyRotationScheduler;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller for key rotation management.
 */
@Controller("/rotation")
public class RotationController {

    private final KeyRotationScheduler rotationScheduler;

    public RotationController(KeyRotationScheduler rotationScheduler) {
        this.rotationScheduler = rotationScheduler;
    }

    /**
     * Manually trigger key rotation.
     *
     * POST /rotation/trigger
     */
    @Post("/trigger")
    public HttpResponse<Map<String, Object>> triggerRotation() {
        boolean success = rotationScheduler.triggerManualRotation();

        Map<String, Object> response = new HashMap<>();
        response.put("success", success);
        response.put("message", success ? "Key rotation completed" : "Key rotation failed");
        response.put("timestamp", java.time.Instant.now().toString());

        return success ? HttpResponse.ok(response) : HttpResponse.serverError(response);
    }

    /**
     * Get rotation status and statistics.
     *
     * GET /rotation/status
     */
    @Get("/status")
    public HttpResponse<Map<String, Object>> getRotationStatus() {
        KeyRotationScheduler.RotationStats stats = rotationScheduler.getStats();

        Map<String, Object> response = new HashMap<>();
        response.put("enabled", stats.enabled());
        response.put("totalRotations", stats.totalRotations());
        response.put("lastRotation", stats.lastRotation().toString());
        response.put("nextRotationIn", formatDuration(stats.timeUntilNext()));
        response.put("nextRotationMinutes", stats.timeUntilNext().toMinutes());

        return HttpResponse.ok(response);
    }

    private String formatDuration(Duration duration) {
        long hours = duration.toHours();
        long minutes = duration.toMinutesPart();
        long seconds = duration.toSecondsPart();

        if (hours > 0) {
            return String.format("%dh %dm %ds", hours, minutes, seconds);
        } else if (minutes > 0) {
            return String.format("%dm %ds", minutes, seconds);
        } else {
            return String.format("%ds", seconds);
        }
    }
}