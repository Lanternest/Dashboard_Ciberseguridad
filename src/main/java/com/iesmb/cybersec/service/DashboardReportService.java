package com.iesmb.cybersec.service;

import com.iesmb.cybersec.dto.projection.OsCountProjection;
import com.iesmb.cybersec.dto.response.SecurityMetricsResponse;
import com.iesmb.cybersec.model.enums.FindingStatus;
import com.iesmb.cybersec.model.enums.Severity;
import com.iesmb.cybersec.repository.ServerAssetRepository;
import com.iesmb.cybersec.repository.VulnerabilityFindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class DashboardReportService {

    private final ServerAssetRepository serverRepository;
    private final VulnerabilityFindingRepository findingRepository;

    @Transactional(readOnly = true)
    public SecurityMetricsResponse getDashboardMetrics() {
        long totalServers = serverRepository.count();
        long exposedServers = serverRepository.findExposedServersNative().size();
        long outdatedOsServers = serverRepository.findOutdatedOsServersNative().size();
        long exposedAndOutdatedServers = serverRepository.findExposedAndOutdatedServersNative().size();
        long exposedWithCritical = serverRepository.findExposedServersWithCriticalVulnerabilitiesNative().size();

        long totalFindings = findingRepository.count();
        long activeFindings = findingRepository.findByStatus(FindingStatus.DETECTED).size();
        long mitigatedFindings = findingRepository.findByStatus(FindingStatus.MITIGATED).size();
        long criticalActiveFindings = findingRepository.findUnmitigatedBySeverityNative(Severity.CRITICAL.name()).size();

        List<OsCountProjection> osProjections = serverRepository.countServersByOsNative();
        Map<String, Long> osDistribution = new HashMap<>();
        for (OsCountProjection p : osProjections) {
            osDistribution.put(p.getOsName(), p.getCount());
        }

        return SecurityMetricsResponse.builder()
                .totalServers(totalServers)
                .exposedServers(exposedServers)
                .outdatedOsServers(outdatedOsServers)
                .exposedAndOutdatedServers(exposedAndOutdatedServers)
                .exposedServersWithCriticalVulnerabilities(exposedWithCritical)
                .totalFindings(totalFindings)
                .activeFindings(activeFindings)
                .mitigatedFindings(mitigatedFindings)
                .criticalActiveFindings(criticalActiveFindings)
                .osDistribution(osDistribution)
                .build();
    }
}
