package com.iesmb.cybersec.controller;

import com.iesmb.cybersec.dto.request.ServerAssetRequest;
import com.iesmb.cybersec.dto.response.ApiMessageResponse;
import com.iesmb.cybersec.dto.response.ServerAssetResponse;
import com.iesmb.cybersec.service.ServerAssetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "2. Gestión de Activos de Red (Servidores)", description = "Registro de servidores, hostnames, IPs y filtros de red mediante consultas nativas JPA.")
@SecurityRequirement(name = "BearerAuth")
@RestController
@RequestMapping("/api/servers")
@RequiredArgsConstructor
public class ServerAssetController {

    private final ServerAssetService serverService;

    @Operation(summary = "Registrar un nuevo servidor en la red")
    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'OPERATOR')")
    public ResponseEntity<ServerAssetResponse> registerServer(
            @Valid @RequestBody ServerAssetRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        ServerAssetResponse response = serverService.registerServer(request, authentication.getName(), httpRequest);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @Operation(summary = "Actualizar información de un servidor")
    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'OPERATOR')")
    public ResponseEntity<ServerAssetResponse> updateServer(
            @PathVariable Long id,
            @Valid @RequestBody ServerAssetRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        ServerAssetResponse response = serverService.updateServer(id, request, authentication.getName(), httpRequest);
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "Eliminar un activo de red (Solo Administrador)")
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiMessageResponse> deleteServer(
            @PathVariable Long id,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        serverService.deleteServer(id, authentication.getName(), httpRequest);
        return ResponseEntity.ok(ApiMessageResponse.builder()
                .success(true)
                .message("Servidor eliminado exitosamente del inventario de red")
                .build());
    }

    @Operation(summary = "Listar todos los servidores registrados")
    @GetMapping
    public ResponseEntity<List<ServerAssetResponse>> getAllServers() {
        return ResponseEntity.ok(serverService.getAllServers());
    }

    @Operation(summary = "Obtener detalle de un servidor por ID")
    @GetMapping("/{id}")
    public ResponseEntity<ServerAssetResponse> getServerById(@PathVariable Long id) {
        return ResponseEntity.ok(serverService.getServerById(id));
    }

    // =========================================================================
    // ENDPOINTS DE CONSULTAS NATIVAS EXIGIDAS (@Query nativeQuery = true)
    // =========================================================================

    @Operation(summary = "Filtrar rápidamente activos de red expuestos (Consulta Nativa JPA)",
            description = "Ejecuta una consulta nativa optimizada en MySQL: SELECT s.* FROM servers s WHERE s.is_exposed = 1")
    @GetMapping("/exposed")
    public ResponseEntity<List<ServerAssetResponse>> getExposedServers() {
        return ResponseEntity.ok(serverService.getExposedServers());
    }

    @Operation(summary = "Filtrar rápidamente servidores con sistemas operativos desactualizados (Consulta Nativa JPA)",
            description = "Ejecuta una consulta nativa optimizada en MySQL: SELECT s.* FROM servers s WHERE s.is_outdated_os = 1")
    @GetMapping("/outdated-os")
    public ResponseEntity<List<ServerAssetResponse>> getOutdatedOsServers() {
        return ResponseEntity.ok(serverService.getOutdatedOsServers());
    }

    @Operation(summary = "Filtrar servidores expuestos con SO desactualizado (Riesgo Crítico Combinado)",
            description = "Consulta nativa: SELECT s.* FROM servers s WHERE s.is_exposed = 1 AND s.is_outdated_os = 1")
    @GetMapping("/exposed-and-outdated")
    public ResponseEntity<List<ServerAssetResponse>> getExposedAndOutdatedServers() {
        return ResponseEntity.ok(serverService.getExposedAndOutdatedServers());
    }

    @Operation(summary = "Filtrar servidores expuestos con vulnerabilidades CRÍTICAS pendientes (Consulta Nativa Join)",
            description = "Consulta nativa multitable entre servers, vulnerability_findings y cves para activos con máxima exposición de riesgo.")
    @GetMapping("/critical-risk")
    public ResponseEntity<List<ServerAssetResponse>> getExposedWithCriticalVulnerabilities() {
        return ResponseEntity.ok(serverService.getExposedWithCriticalVulnerabilities());
    }

    @Operation(summary = "Filtrar servidores por prefijo o subred de IP (Consulta Nativa)")
    @GetMapping("/subnet/{prefix}")
    public ResponseEntity<List<ServerAssetResponse>> getServersBySubnet(@PathVariable String prefix) {
        return ResponseEntity.ok(serverService.getServersBySubnet(prefix));
    }
}
