package com.iesmb.cybersec.controller;

import com.iesmb.cybersec.dto.response.SecurityMetricsResponse;
import com.iesmb.cybersec.service.DashboardReportService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "7. Dashboard & Reportes de Ciberseguridad", description = "Métricas y resumen ejecutivo de la postura de seguridad y activos de red.")
@SecurityRequirement(name = "BearerAuth")
@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardReportController {

    private final DashboardReportService dashboardReportService;

    @Operation(summary = "Obtener métricas consolidadas del Dashboard de Ciberseguridad",
            description = "Devuelve estadísticas en tiempo real: servidores expuestos, sistemas operativos obsoletos, vulnerabilidades críticas activas y mitigadas, y distribución de sistemas operativos.")
    @GetMapping("/metrics")
    public ResponseEntity<SecurityMetricsResponse> getDashboardMetrics() {
        return ResponseEntity.ok(dashboardReportService.getDashboardMetrics());
    }
}
