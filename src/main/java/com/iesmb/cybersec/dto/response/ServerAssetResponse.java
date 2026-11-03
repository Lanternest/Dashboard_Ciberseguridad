package com.iesmb.cybersec.dto.response;

import com.iesmb.cybersec.model.enums.Environment;
import com.iesmb.cybersec.model.enums.ServerStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ServerAssetResponse {

    private Long id;
    private String hostname;
    private String ipAddress;
    private String macAddress;
    private String operatingSystem;
    private String osVersion;
    private Environment environment;
    private boolean isExposed;
    private boolean isOutdatedOs;
    private ServerStatus status;
    private String location;
    private String description;
    private int activeFindingsCount;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
