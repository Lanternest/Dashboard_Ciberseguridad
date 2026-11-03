package com.iesmb.cybersec.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityMetricsResponse {

    private long totalServers;
    private long exposedServers;
    private long outdatedOsServers;
    private long exposedAndOutdatedServers;
    private long exposedServersWithCriticalVulnerabilities;

    private long totalFindings;
    private long activeFindings;
    private long mitigatedFindings;
    private long criticalActiveFindings;

    private Map<String, Long> osDistribution;
}
