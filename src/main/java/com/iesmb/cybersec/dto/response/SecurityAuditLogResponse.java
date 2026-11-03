package com.iesmb.cybersec.dto.response;

import com.iesmb.cybersec.model.enums.AuditEventType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityAuditLogResponse {

    private Long id;
    private AuditEventType eventType;
    private String action;
    private String performedBy;
    private String sourceIp;
    private String targetEntity;
    private String targetId;
    private String details;
    private LocalDateTime timestamp;
}
