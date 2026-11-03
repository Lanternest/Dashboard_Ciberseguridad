package com.iesmb.cybersec.service;

import com.iesmb.cybersec.dto.response.SecurityAuditLogResponse;
import com.iesmb.cybersec.model.entity.SecurityAuditLog;
import com.iesmb.cybersec.model.enums.AuditEventType;
import com.iesmb.cybersec.repository.SecurityAuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityAuditLogService {

    private final SecurityAuditLogRepository auditLogRepository;

    @Transactional
    public SecurityAuditLog logEvent(AuditEventType eventType,
                                     String action,
                                     String performedBy,
                                     String sourceIp,
                                     String targetEntity,
                                     String targetId,
                                     String details) {
        SecurityAuditLog auditLog = SecurityAuditLog.builder()
                .eventType(eventType)
                .action(action)
                .performedBy(performedBy != null ? performedBy : "ANONYMOUS")
                .sourceIp(sourceIp != null ? sourceIp : "127.0.0.1")
                .targetEntity(targetEntity)
                .targetId(targetId)
                .details(details)
                .build();

        log.info("[AUDIT-LOG] Evento: {} | Acción: {} | Usuario: {} | IP Origen: {} | Entidad: {}#{}",
                eventType, action, performedBy, sourceIp, targetEntity, targetId);

        return auditLogRepository.save(auditLog);
    }

    @Transactional(readOnly = true)
    public List<SecurityAuditLogResponse> getRecentAudits(int limit) {
        return auditLogRepository.findRecentEventsNative(limit).stream()
                .map(this::mapToResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<SecurityAuditLogResponse> getAuditsByEventType(String eventType) {
        return auditLogRepository.findByEventTypeNative(eventType).stream()
                .map(this::mapToResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<SecurityAuditLogResponse> getAuditsBySourceIp(String sourceIp) {
        return auditLogRepository.findBySourceIpNative(sourceIp).stream()
                .map(this::mapToResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<SecurityAuditLogResponse> getAuditsByPerformedBy(String username) {
        return auditLogRepository.findByPerformedByNative(username).stream()
                .map(this::mapToResponse)
                .toList();
    }

    public SecurityAuditLogResponse mapToResponse(SecurityAuditLog log) {
        return SecurityAuditLogResponse.builder()
                .id(log.getId())
                .eventType(log.getEventType())
                .action(log.getAction())
                .performedBy(log.getPerformedBy())
                .sourceIp(log.getSourceIp())
                .targetEntity(log.getTargetEntity())
                .targetId(log.getTargetId())
                .details(log.getDetails())
                .timestamp(log.getTimestamp())
                .build();
    }
}
