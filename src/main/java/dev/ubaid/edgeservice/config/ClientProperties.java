package dev.ubaid.edgeservice.config;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "polar")
public record ClientProperties(
    @NotNull
    String homeMessage
) { }
