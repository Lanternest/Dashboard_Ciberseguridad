package com.iesmb.cybersec.service;

import com.iesmb.cybersec.dto.request.ServerAssetRequest;
import com.iesmb.cybersec.dto.response.ServerAssetResponse;
import com.iesmb.cybersec.exception.BadRequestException;
import com.iesmb.cybersec.exception.ResourceNotFoundException;
import com.iesmb.cybersec.model.entity.ServerAsset;
import com.iesmb.cybersec.model.enums.AuditEventType;
import com.iesmb.cybersec.model.enums.FindingStatus;
import com.iesmb.cybersec.repository.ServerAssetRepository;
import com.iesmb.cybersec.util.ClientIpUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ServerAssetService {

    private final ServerAssetRepository serverRepository;
    private final SecurityAuditLogService auditLogService;

    @Transactional
    public ServerAssetResponse registerServer(ServerAssetRequest request, String username, HttpServletRequest httpRequest) {
        String clientIp = ClientIpUtil.getClientIp(httpRequest);

        if (serverRepository.existsByHostname(request.getHostname())) {
            throw new BadRequestException("Ya existe un servidor registrado con el hostname: " + request.getHostname());
        }

        if (serverRepository.existsByIpAddress(request.getIpAddress())) {
            throw new BadRequestException("Ya existe un servidor registrado con la dirección IP: " + request.getIpAddress());
        }

        ServerAsset server = ServerAsset.builder()
                .hostname(request.getHostname())
                .ipAddress(request.getIpAddress())
                .macAddress(request.getMacAddress())
                .operatingSystem(request.getOperatingSystem())
                .osVersion(request.getOsVersion())
                .environment(request.getEnvironment())
                .isExposed(request.isExposed())
                .isOutdatedOs(request.isOutdatedOs())
                .status(request.getStatus() != null ? request.getStatus() : com.iesmb.cybersec.model.enums.ServerStatus.ONLINE)
                .location(request.getLocation())
                .description(request.getDescription())
                .build();

        ServerAsset saved = serverRepository.save(server);

        auditLogService.logEvent(
                AuditEventType.SERVER_REGISTERED,
                "Registro de nuevo activo de red en inventario",
                username,
                clientIp,
                "SERVER",
                String.valueOf(saved.getId()),
                String.format("Hostname: %s, IP: %s, Expuesto: %b, SO Desactualizado: %b",
                        saved.getHostname(), saved.getIpAddress(), saved.isExposed(), saved.isOutdatedOs())
        );

        return mapToResponse(saved);
    }

    @Transactional
    public ServerAssetResponse updateServer(Long id, ServerAssetRequest request, String username, HttpServletRequest httpRequest) {
        String clientIp = ClientIpUtil.getClientIp(httpRequest);

        ServerAsset server = serverRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Servidor no encontrado con ID: " + id));

        if (!server.getHostname().equalsIgnoreCase(request.getHostname()) && serverRepository.existsByHostname(request.getHostname())) {
            throw new BadRequestException("El hostname '" + request.getHostname() + "' ya pertenece a otro servidor");
        }

        if (!server.getIpAddress().equalsIgnoreCase(request.getIpAddress()) && serverRepository.existsByIpAddress(request.getIpAddress())) {
            throw new BadRequestException("La dirección IP '" + request.getIpAddress() + "' ya pertenece a otro servidor");
        }

        server.setHostname(request.getHostname());
        server.setIpAddress(request.getIpAddress());
        server.setMacAddress(request.getMacAddress());
        server.setOperatingSystem(request.getOperatingSystem());
        server.setOsVersion(request.getOsVersion());
        server.setEnvironment(request.getEnvironment());
        server.setExposed(request.isExposed());
        server.setOutdatedOs(request.isOutdatedOs());
        if (request.getStatus() != null) {
            server.setStatus(request.getStatus());
        }
        server.setLocation(request.getLocation());
        server.setDescription(request.getDescription());

        ServerAsset updated = serverRepository.save(server);

        auditLogService.logEvent(
                AuditEventType.SERVER_UPDATED,
                "Actualización de parámetros de activo de red",
                username,
                clientIp,
                "SERVER",
                String.valueOf(updated.getId()),
                String.format("Hostname: %s, IP: %s, Expuesto: %b, SO Desactualizado: %b",
                        updated.getHostname(), updated.getIpAddress(), updated.isExposed(), updated.isOutdatedOs())
        );

        return mapToResponse(updated);
    }

    @Transactional
    public void deleteServer(Long id, String username, HttpServletRequest httpRequest) {
        String clientIp = ClientIpUtil.getClientIp(httpRequest);

        ServerAsset server = serverRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Servidor no encontrado con ID: " + id));

        serverRepository.delete(server);

        auditLogService.logEvent(
                AuditEventType.SERVER_DELETED,
                "Baja definitiva de activo de red",
                username,
                clientIp,
                "SERVER",
                String.valueOf(id),
                "Servidor eliminado: " + server.getHostname() + " (" + server.getIpAddress() + ")"
        );
    }

    @Transactional(readOnly = true)
    public List<ServerAssetResponse> getAllServers() {
        return serverRepository.findAll().stream()
                .map(this::mapToResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public ServerAssetResponse getServerById(Long id) {
        ServerAsset server = serverRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Servidor no encontrado con ID: " + id));
        return mapToResponse(server);
    }

    // =========================================================================
    // FILTROS RÁPIDOS MEDIANTE CONSULTAS NATIVAS JPA (@Query nativeQuery = true)
    // =========================================================================

    @Transactional(readOnly = true)
    public List<ServerAssetResponse> getExposedServers() {
        return serverRepository.findExposedServersNative().stream()
                .map(this::mapToResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ServerAssetResponse> getOutdatedOsServers() {
        return serverRepository.findOutdatedOsServersNative().stream()
                .map(this::mapToResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ServerAssetResponse> getExposedAndOutdatedServers() {
        return serverRepository.findExposedAndOutdatedServersNative().stream()
                .map(this::mapToResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ServerAssetResponse> getExposedWithCriticalVulnerabilities() {
        return serverRepository.findExposedServersWithCriticalVulnerabilitiesNative().stream()
                .map(this::mapToResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ServerAssetResponse> getServersBySubnet(String prefix) {
        return serverRepository.findByIpSubnetNative(prefix).stream()
                .map(this::mapToResponse)
                .toList();
    }

    public ServerAssetResponse mapToResponse(ServerAsset server) {
        int activeFindings = (int) server.getFindings().stream()
                .filter(f -> f.getStatus() == FindingStatus.DETECTED)
                .count();

        return ServerAssetResponse.builder()
                .id(server.getId())
                .hostname(server.getHostname())
                .ipAddress(server.getIpAddress())
                .macAddress(server.getMacAddress())
                .operatingSystem(server.getOperatingSystem())
                .osVersion(server.getOsVersion())
                .environment(server.getEnvironment())
                .isExposed(server.isExposed())
                .isOutdatedOs(server.isOutdatedOs())
                .status(server.getStatus())
                .location(server.getLocation())
                .description(server.getDescription())
                .activeFindingsCount(activeFindings)
                .createdAt(server.getCreatedAt())
                .updatedAt(server.getUpdatedAt())
                .build();
    }
}
