package com.iesmb.cybersec.controller;

import com.iesmb.cybersec.dto.response.SecurityAuditLogResponse;
import com.iesmb.cybersec.service.SecurityAuditLogService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "6. Logs de Auditoría Forense", description = "Trazabilidad de cada evento de seguridad del sistema (quién, qué, cuándo e IP de origen).")
@SecurityRequirement(name = "BearerAuth")
@RestController
@RequestMapping("/api/audit-logs")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('ADMIN', 'AUDITOR')")
public class SecurityAuditLogController {

    private final SecurityAuditLogService auditLogService;

    @Operation(summary = "Obtener los últimos N eventos de auditoría de seguridad")
    @GetMapping("/recent")
    public ResponseEntity<List<SecurityAuditLogResponse>> getRecentAudits(
            @RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(auditLogService.getRecentAudits(limit));
    }

    @Operation(summary = "Filtrar logs de auditoría por tipo de evento (Consulta Nativa JPA)",
            description = "Ejemplos: VULNERABILITY_REPORTED, VULNERABILITY_MITIGATED, SERVER_REGISTERED, USER_LOGIN_SUCCESS, USER_LOGIN_FAILED")
    @GetMapping("/event-type/{eventType}")
    public ResponseEntity<List<SecurityAuditLogResponse>> getAuditsByEventType(@PathVariable String eventType) {
        return ResponseEntity.ok(auditLogService.getAuditsByEventType(eventType));
    }

    @Operation(summary = "Rastrear eventos por dirección IP de origen (Filtro Nativo Forense)")
    @GetMapping("/source-ip/{sourceIp}")
    public ResponseEntity<List<SecurityAuditLogResponse>> getAuditsBySourceIp(@PathVariable String sourceIp) {
        return ResponseEntity.ok(auditLogService.getAuditsBySourceIp(sourceIp));
    }

    @Operation(summary = "Rastrear eventos por usuario operador/auditor (Filtro Nativo)")
    @GetMapping("/user/{username}")
    public ResponseEntity<List<SecurityAuditLogResponse>> getAuditsByPerformedBy(@PathVariable String username) {
        return ResponseEntity.ok(auditLogService.getAuditsByPerformedBy(username));
    }
}
