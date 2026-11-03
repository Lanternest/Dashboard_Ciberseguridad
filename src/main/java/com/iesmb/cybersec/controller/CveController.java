package com.iesmb.cybersec.controller;

import com.iesmb.cybersec.dto.request.CveRequest;
import com.iesmb.cybersec.dto.response.CveResponse;
import com.iesmb.cybersec.service.CveService;
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

@Tag(name = "3. Catálogo de Vulnerabilidades (CVEs)", description = "Mapeo de vulnerabilidades comunes y exposiciones (CVE IDs, severidad CVSS y guías de remediación).")
@SecurityRequirement(name = "BearerAuth")
@RestController
@RequestMapping("/api/cves")
@RequiredArgsConstructor
public class CveController {

    private final CveService cveService;

    @Operation(summary = "Registrar un nuevo CVE en el catálogo")
    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'AUDITOR')")
    public ResponseEntity<CveResponse> createCve(
            @Valid @RequestBody CveRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        CveResponse response = cveService.createCve(request, authentication.getName(), httpRequest);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @Operation(summary = "Listar todas las vulnerabilidades CVE registradas")
    @GetMapping
    public ResponseEntity<List<CveResponse>> getAllCves() {
        return ResponseEntity.ok(cveService.getAllCves());
    }

    @Operation(summary = "Buscar detalle de un CVE por código (ej: CVE-2021-44228)")
    @GetMapping("/{cveCode}")
    public ResponseEntity<CveResponse> getCveByCode(@PathVariable String cveCode) {
        return ResponseEntity.ok(cveService.getCveByCode(cveCode));
    }

    @Operation(summary = "Filtrar CVEs por severidad mediante Consulta Nativa (LOW, MEDIUM, HIGH, CRITICAL)")
    @GetMapping("/severity/{severity}")
    public ResponseEntity<List<CveResponse>> getCvesBySeverity(@PathVariable String severity) {
        return ResponseEntity.ok(cveService.getCvesBySeverity(severity));
    }
}
