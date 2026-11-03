package com.iesmb.cybersec.config;

import com.iesmb.cybersec.model.entity.*;
import com.iesmb.cybersec.model.enums.*;
import com.iesmb.cybersec.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final ServerAssetRepository serverRepository;
    private final CveRepository cveRepository;
    private final VulnerabilityScanRepository scanRepository;
    private final VulnerabilityFindingRepository findingRepository;
    private final SecurityAuditLogRepository auditLogRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(String... args) {
        if (userRepository.count() > 0) {
            log.info("La base de datos ya cuenta con datos iniciales. Omitiendo seed.");
            return;
        }

        log.info("Iniciando sembrado (seeding) de datos de ciberseguridad y auditoría...");

        // 1. Usuarios con roles
        User admin = userRepository.save(User.builder()
                .username("admin")
                .password(passwordEncoder.encode("Admin123!"))
                .email("admin@iesmb.edu.ar")
                .fullName("Administrador de Seguridad")
                .role(Role.ROLE_ADMIN)
                .enabled(true)
                .build());

        User auditor = userRepository.save(User.builder()
                .username("auditor")
                .password(passwordEncoder.encode("Auditor123!"))
                .email("auditor@iesmb.edu.ar")
                .fullName("Auditor Senior Ciberseguridad")
                .role(Role.ROLE_AUDITOR)
                .enabled(true)
                .build());

        User operator = userRepository.save(User.builder()
                .username("operator")
                .password(passwordEncoder.encode("Operator123!"))
                .email("operator@iesmb.edu.ar")
                .fullName("Operador de Monitoreo SOC")
                .role(Role.ROLE_OPERATOR)
                .enabled(true)
                .build());

        log.info("Usuarios creados: admin/Admin123!, auditor/Auditor123!, operator/Operator123!");

        // 2. Catálogo de CVEs
        Cve cveLog4j = cveRepository.save(Cve.builder()
                .cveCode("CVE-2021-44228")
                .title("Apache Log4j Remote Code Execution (Log4Shell)")
                .description("Vulnerabilidad crítica en el análisis de expresiones JNDI que permite ejecución remota de código.")
                .cvssScore(10.0)
                .severity(Severity.CRITICAL)
                .publishedDate(LocalDate.of(2021, 12, 10))
                .remediationGuide("Actualizar a Log4j 2.17.1 o superior o configurar -Dlog4j2.formatMsgNoLookups=true.")
                .build());

        Cve cveEternalBlue = cveRepository.save(Cve.builder()
                .cveCode("CVE-2017-0144")
                .title("Microsoft SMBv1 Remote Code Execution (EternalBlue)")
                .description("Falla crítica en el protocolo SMBv1 que permite enviar paquetes especialmente diseñados para ejecutar código arbitrario.")
                .cvssScore(9.8)
                .severity(Severity.CRITICAL)
                .publishedDate(LocalDate.of(2017, 3, 14))
                .remediationGuide("Aplicar parche MS17-010 y deshabilitar completamente SMBv1.")
                .build());

        Cve cveXz = cveRepository.save(Cve.builder()
                .cveCode("CVE-2024-3094")
                .title("XZ Utils Backdoor en liblzma")
                .description("Inyección maliciosa de código en liblzma que intercepta la autenticación OpenSSH mediante RSA.")
                .cvssScore(10.0)
                .severity(Severity.CRITICAL)
                .publishedDate(LocalDate.of(2024, 3, 29))
                .remediationGuide("Revertir xz-utils a versión 5.4.x o posterior no afectada.")
                .build());

        Cve cveHttp2 = cveRepository.save(Cve.builder()
                .cveCode("CVE-2023-44487")
                .title("HTTP/2 Rapid Reset Attack")
                .description("Agotamiento masivo de recursos por cancelación inmediata de streams en conexiones HTTP/2.")
                .cvssScore(7.5)
                .severity(Severity.HIGH)
                .publishedDate(LocalDate.of(2023, 10, 10))
                .remediationGuide("Habilitar límites de concurrencia de stream en proxies inversos Nginx/Apache.")
                .build());

        Cve cveConfluence = cveRepository.save(Cve.builder()
                .cveCode("CVE-2023-22515")
                .title("Atlassian Confluence Data Center Broken Access Control")
                .description("Falla de control de acceso que permite a atacantes no autenticados crear cuentas de administrador no autorizadas.")
                .cvssScore(9.8)
                .severity(Severity.CRITICAL)
                .publishedDate(LocalDate.of(2023, 10, 4))
                .remediationGuide("Actualizar Confluence a versiones 8.3.3, 8.4.3, 8.5.2 o superiores.")
                .build());

        // 3. Activos de red (Servidores)
        ServerAsset srvProdWeb = serverRepository.save(ServerAsset.builder()
                .hostname("srv-prod-web01")
                .ipAddress("198.51.100.14")
                .macAddress("00:50:56:A1:B2:C1")
                .operatingSystem("Ubuntu")
                .osVersion("22.04 LTS")
                .environment(Environment.PRODUCTION)
                .isExposed(true)
                .isOutdatedOs(false)
                .status(ServerStatus.ONLINE)
                .location("Datacenter Buenos Aires - Rack A4")
                .description("Servidor Web Frontend público")
                .build());

        ServerAsset srvEdgeGateway = serverRepository.save(ServerAsset.builder()
                .hostname("srv-edge-gateway01")
                .ipAddress("203.0.113.88")
                .macAddress("00:50:56:C3:D4:E2")
                .operatingSystem("CentOS")
                .osVersion("7.9")
                .environment(Environment.PRODUCTION)
                .isExposed(true)
                .isOutdatedOs(true) // Expuesto y desactualizado (Riesgo máximo)
                .status(ServerStatus.ONLINE)
                .location("Datacenter Buenos Aires - DMZ")
                .description("Gateway perimetral y balanceador DMZ obsoleto")
                .build());

        ServerAsset srvLegacyDb = serverRepository.save(ServerAsset.builder()
                .hostname("srv-legacy-db01")
                .ipAddress("10.0.4.15")
                .macAddress("00:50:56:E5:F6:A3")
                .operatingSystem("Windows Server")
                .osVersion("2008 R2")
                .environment(Environment.STAGING)
                .isExposed(false)
                .isOutdatedOs(true) // SO fuera de soporte
                .status(ServerStatus.ONLINE)
                .location("Site Secundario Córdoba - Rack B1")
                .description("Base de datos de facturación histórica heredada")
                .build());

        ServerAsset srvInternalApp = serverRepository.save(ServerAsset.builder()
                .hostname("srv-internal-app01")
                .ipAddress("10.0.2.20")
                .macAddress("00:50:56:B7:C8:D4")
                .operatingSystem("Debian")
                .osVersion("12 Bookworm")
                .environment(Environment.DEVELOPMENT)
                .isExposed(false)
                .isOutdatedOs(false)
                .status(ServerStatus.ONLINE)
                .location("Nube Privada On-Premise")
                .description("Servidor de aplicaciones internas")
                .build());

        ServerAsset srvDmzApi = serverRepository.save(ServerAsset.builder()
                .hostname("srv-dmz-api01")
                .ipAddress("198.51.100.50")
                .macAddress("00:50:56:9A:8B:7C")
                .operatingSystem("Ubuntu")
                .osVersion("20.04 LTS")
                .environment(Environment.PRODUCTION)
                .isExposed(true)
                .isOutdatedOs(false)
                .status(ServerStatus.ONLINE)
                .location("Datacenter Buenos Aires - DMZ")
                .description("API Gateway público para integraciones de clientes")
                .build());

        // 4. Escaneos de vulnerabilidades
        VulnerabilityScan scanNessus = scanRepository.save(VulnerabilityScan.builder()
                .scanCode("SCAN-202610-001")
                .scannerTool("Nessus Professional v10.7")
                .status(ScanStatus.COMPLETED)
                .targetRange("198.51.100.0/24")
                .scannedBy("auditor")
                .sourceIp("192.168.10.55")
                .startedAt(LocalDateTime.now().minusDays(2))
                .finishedAt(LocalDateTime.now().minusDays(2).plusHours(1))
                .summary("Escaneo trimestral de activos expuestos a la DMZ pública.")
                .build());

        VulnerabilityScan scanOpenVas = scanRepository.save(VulnerabilityScan.builder()
                .scanCode("SCAN-202610-002")
                .scannerTool("OpenVAS / Greenbone Community")
                .status(ScanStatus.COMPLETED)
                .targetRange("10.0.0.0/16")
                .scannedBy("operator")
                .sourceIp("10.0.1.5")
                .startedAt(LocalDateTime.now().minusDays(1))
                .finishedAt(LocalDateTime.now().minusDays(1).plusHours(2))
                .summary("Escaneo interno de la red corporativa y servidores heredados.")
                .build());

        // 5. Hallazgos de vulnerabilidades con auditoría obligatoria
        // Finding 1: Activo en servidor expuesto con Log4Shell (Riesgo Crítico)
        findingRepository.save(VulnerabilityFinding.builder()
                .server(srvEdgeGateway)
                .cve(cveLog4j)
                .scan(scanNessus)
                .port(8080)
                .protocol("TCP")
                .status(FindingStatus.DETECTED)
                .reportedBy("auditor")
                .reportedAt(LocalDateTime.now().minusDays(2))
                .reporterIp("192.168.10.55")
                .build());

        // Finding 2: Activo en servidor perimetral con HTTP/2 Rapid Reset
        findingRepository.save(VulnerabilityFinding.builder()
                .server(srvProdWeb)
                .cve(cveHttp2)
                .scan(scanNessus)
                .port(443)
                .protocol("TCP")
                .status(FindingStatus.DETECTED)
                .reportedBy("auditor")
                .reportedAt(LocalDateTime.now().minusDays(2))
                .reporterIp("192.168.10.55")
                .build());

        // Finding 3: Activo en base de datos heredada con EternalBlue
        findingRepository.save(VulnerabilityFinding.builder()
                .server(srvLegacyDb)
                .cve(cveEternalBlue)
                .scan(scanOpenVas)
                .port(445)
                .protocol("TCP")
                .status(FindingStatus.DETECTED)
                .reportedBy("operator")
                .reportedAt(LocalDateTime.now().minusDays(1))
                .reporterIp("10.0.1.5")
                .build());

        // Finding 4: Mitigado en servidor DMZ API
        findingRepository.save(VulnerabilityFinding.builder()
                .server(srvDmzApi)
                .cve(cveXz)
                .scan(scanNessus)
                .port(22)
                .protocol("TCP")
                .status(FindingStatus.MITIGATED)
                .reportedBy("auditor")
                .reportedAt(LocalDateTime.now().minusDays(5))
                .reporterIp("192.168.10.55")
                .mitigatedBy("admin")
                .mitigatedAt(LocalDateTime.now().minusDays(3))
                .mitigatorIp("192.168.10.100")
                .mitigationNotes("Se revirtió paquete liblzma a la versión 5.4.5 y se reinició el servicio SSHD.")
                .build());

        // 6. Logs en tabla de auditoría central
        auditLogRepository.save(SecurityAuditLog.builder()
                .eventType(AuditEventType.SERVER_REGISTERED)
                .action("Registro de servidor perimetral crítico")
                .performedBy("admin")
                .sourceIp("192.168.10.100")
                .targetEntity("SERVER")
                .targetId(String.valueOf(srvEdgeGateway.getId()))
                .details("Hostname: srv-edge-gateway01, IP: 203.0.113.88, Expuesto: true, SO Desactualizado: true")
                .timestamp(LocalDateTime.now().minusDays(6))
                .build());

        auditLogRepository.save(SecurityAuditLog.builder()
                .eventType(AuditEventType.VULNERABILITY_REPORTED)
                .action("Detección de vulnerabilidad Log4Shell")
                .performedBy("auditor")
                .sourceIp("192.168.10.55")
                .targetEntity("FINDING")
                .targetId("1")
                .details("CVE-2021-44228 reportado en puerto 8080 de srv-edge-gateway01")
                .timestamp(LocalDateTime.now().minusDays(2))
                .build());

        auditLogRepository.save(SecurityAuditLog.builder()
                .eventType(AuditEventType.VULNERABILITY_MITIGATED)
                .action("Mitigación exitosa de CVE-2024-3094")
                .performedBy("admin")
                .sourceIp("192.168.10.100")
                .targetEntity("FINDING")
                .targetId("4")
                .details("Parche aplicado en srv-dmz-api01 (liblzma revertido)")
                .timestamp(LocalDateTime.now().minusDays(3))
                .build());

        log.info("Sembrado inicial de datos completado exitosamente.");
    }
}
