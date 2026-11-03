package com.iesmb.cybersec;

import com.iesmb.cybersec.dto.projection.OsCountProjection;
import com.iesmb.cybersec.model.entity.SecurityAuditLog;
import com.iesmb.cybersec.model.entity.ServerAsset;
import com.iesmb.cybersec.model.entity.VulnerabilityFinding;
import com.iesmb.cybersec.repository.SecurityAuditLogRepository;
import com.iesmb.cybersec.repository.ServerAssetRepository;
import com.iesmb.cybersec.repository.VulnerabilityFindingRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Transactional
class NativeQueryRepositoriesTest {

    @Autowired
    private ServerAssetRepository serverRepository;

    @Autowired
    private VulnerabilityFindingRepository findingRepository;

    @Autowired
    private SecurityAuditLogRepository auditLogRepository;

    @Test
    @DisplayName("Consulta nativa: filtrar rápidamente activos de red expuestos a internet (is_exposed = 1)")
    void testFindExposedServersNative() {
        List<ServerAsset> exposedServers = serverRepository.findExposedServersNative();

        assertThat(exposedServers).isNotEmpty();
        assertThat(exposedServers).allMatch(ServerAsset::isExposed);
    }

    @Test
    @DisplayName("Consulta nativa: filtrar rápidamente sistemas operativos desactualizados (is_outdated_os = 1)")
    void testFindOutdatedOsServersNative() {
        List<ServerAsset> outdatedServers = serverRepository.findOutdatedOsServersNative();

        assertThat(outdatedServers).isNotEmpty();
        assertThat(outdatedServers).allMatch(ServerAsset::isOutdatedOs);
    }

    @Test
    @DisplayName("Consulta nativa combinada: servidores expuestos Y con SO desactualizado")
    void testFindExposedAndOutdatedServersNative() {
        List<ServerAsset> exposedAndOutdated = serverRepository.findExposedAndOutdatedServersNative();

        assertThat(exposedAndOutdated).isNotEmpty();
        assertThat(exposedAndOutdated).allMatch(s -> s.isExposed() && s.isOutdatedOs());
    }

    @Test
    @DisplayName("Consulta nativa agregada: distribución de servidores por sistema operativo")
    void testCountServersByOsNative() {
        List<OsCountProjection> osDistribution = serverRepository.countServersByOsNative();

        assertThat(osDistribution).isNotEmpty();
        assertThat(osDistribution.getFirst().getOsName()).isNotBlank();
        assertThat(osDistribution.getFirst().getCount()).isGreaterThan(0);
    }

    @Test
    @DisplayName("Auditoría en MySQL: verificar campos de reporte (quién, cuándo, IP origen) y mitigación")
    void testAuditFieldsInFindings() {
        List<VulnerabilityFinding> findings = findingRepository.findAll();

        assertThat(findings).isNotEmpty();

        // Verificar que los reportes registran quién, cuándo y la IP de origen
        for (VulnerabilityFinding f : findings) {
            assertThat(f.getReportedBy()).isNotBlank();
            assertThat(f.getReportedAt()).isNotNull();
            assertThat(f.getReporterIp()).isNotBlank();
        }

        // Verificar consulta nativa de mitigados
        List<VulnerabilityFinding> mitigated = findingRepository.findMitigatedFindingsNative();
        assertThat(mitigated).isNotEmpty();
        for (VulnerabilityFinding m : mitigated) {
            assertThat(m.getMitigatedBy()).isNotBlank();
            assertThat(m.getMitigatedAt()).isNotNull();
            assertThat(m.getMitigatorIp()).isNotBlank();
            assertThat(m.getMitigationNotes()).isNotBlank();
        }
    }

    @Test
    @DisplayName("Auditoría en MySQL: trazabilidad forense en tabla security_audit_logs")
    void testSecurityAuditLogs() {
        List<SecurityAuditLog> logs = auditLogRepository.findRecentEventsNative(20);

        assertThat(logs).isNotEmpty();
        for (SecurityAuditLog l : logs) {
            assertThat(l.getEventType()).isNotNull();
            assertThat(l.getPerformedBy()).isNotBlank();
            assertThat(l.getSourceIp()).isNotBlank();
            assertThat(l.getTimestamp()).isNotNull();
        }
    }
}
