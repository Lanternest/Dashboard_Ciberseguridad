package com.iesmb.cybersec.service;

import com.iesmb.cybersec.dto.request.CveRequest;
import com.iesmb.cybersec.dto.response.CveResponse;
import com.iesmb.cybersec.exception.BadRequestException;
import com.iesmb.cybersec.exception.ResourceNotFoundException;
import com.iesmb.cybersec.model.entity.Cve;
import com.iesmb.cybersec.model.enums.AuditEventType;
import com.iesmb.cybersec.repository.CveRepository;
import com.iesmb.cybersec.util.ClientIpUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CveService {

    private final CveRepository cveRepository;
    private final SecurityAuditLogService auditLogService;

    @Transactional
    public CveResponse createCve(CveRequest request, String username, HttpServletRequest httpRequest) {
        String clientIp = ClientIpUtil.getClientIp(httpRequest);

        if (cveRepository.existsByCveCode(request.getCveCode())) {
            throw new BadRequestException("El identificador CVE ya está registrado: " + request.getCveCode());
        }

        Cve cve = Cve.builder()
                .cveCode(request.getCveCode().toUpperCase().trim())
                .title(request.getTitle())
                .description(request.getDescription())
                .cvssScore(request.getCvssScore())
                .severity(request.getSeverity())
                .publishedDate(request.getPublishedDate())
                .remediationGuide(request.getRemediationGuide())
                .build();

        Cve saved = cveRepository.save(cve);

        auditLogService.logEvent(
                AuditEventType.CVE_REGISTERED,
                "Registro de vulnerabilidad conocida (CVE) en el catálogo de seguridad",
                username,
                clientIp,
                "CVE",
                saved.getCveCode(),
                "Severidad: " + saved.getSeverity() + ", Score CVSS: " + saved.getCvssScore()
        );

        return mapToResponse(saved);
    }

    @Transactional(readOnly = true)
    public List<CveResponse> getAllCves() {
        return cveRepository.findAll().stream()
                .map(this::mapToResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public CveResponse getCveByCode(String cveCode) {
        Cve cve = cveRepository.findByCveCode(cveCode.toUpperCase().trim())
                .orElseThrow(() -> new ResourceNotFoundException("CVE no encontrado: " + cveCode));
        return mapToResponse(cve);
    }

    @Transactional(readOnly = true)
    public List<CveResponse> getCvesBySeverity(String severity) {
        return cveRepository.findBySeverityNative(severity.toUpperCase().trim()).stream()
                .map(this::mapToResponse)
                .toList();
    }

    public CveResponse mapToResponse(Cve cve) {
        return CveResponse.builder()
                .id(cve.getId())
                .cveCode(cve.getCveCode())
                .title(cve.getTitle())
                .description(cve.getDescription())
                .cvssScore(cve.getCvssScore())
                .severity(cve.getSeverity())
                .publishedDate(cve.getPublishedDate())
                .remediationGuide(cve.getRemediationGuide())
                .build();
    }
}
