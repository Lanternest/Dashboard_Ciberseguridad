package com.iesmb.cybersec.dto.request;

import com.iesmb.cybersec.model.enums.Environment;
import com.iesmb.cybersec.model.enums.ServerStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ServerAssetRequest {

    @NotBlank(message = "El hostname del servidor es obligatorio")
    private String hostname;

    @NotBlank(message = "La dirección IP es obligatoria")
    @Pattern(
            regexp = "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
            message = "La dirección IP debe ser un formato válido IPv4 o IPv6"
    )
    private String ipAddress;

    private String macAddress;

    @NotBlank(message = "El sistema operativo es obligatorio")
    private String operatingSystem;

    @NotBlank(message = "La versión del sistema operativo es obligatoria")
    private String osVersion;

    @NotNull(message = "El entorno es obligatorio (PRODUCTION, STAGING, DEVELOPMENT, TEST)")
    private Environment environment;

    private boolean isExposed;

    private boolean isOutdatedOs;

    private ServerStatus status;

    private String location;

    private String description;
}
