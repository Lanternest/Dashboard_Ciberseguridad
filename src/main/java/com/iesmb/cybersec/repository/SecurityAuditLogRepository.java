package com.iesmb.cybersec.repository;

import com.iesmb.cybersec.model.entity.SecurityAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SecurityAuditLogRepository extends JpaRepository<SecurityAuditLog, Long> {

    // =========================================================================
    // CONSULTAS NATIVAS DE TABLA DE AUDITORÍA
    // =========================================================================

    /**
     * Consulta nativa para filtrar eventos de auditoría por tipo de evento.
     */
    @Query(value = "SELECT * FROM security_audit_logs WHERE event_type = :eventType ORDER BY timestamp DESC", nativeQuery = true)
    List<SecurityAuditLog> findByEventTypeNative(@Param("eventType") String eventType);

    /**
     * Consulta nativa para rastrear todas las acciones ejecutadas desde una dirección IP de origen específica.
     */
    @Query(value = "SELECT * FROM security_audit_logs WHERE source_ip = :sourceIp ORDER BY timestamp DESC", nativeQuery = true)
    List<SecurityAuditLog> findBySourceIpNative(@Param("sourceIp") String sourceIp);

    /**
     * Consulta nativa para rastrear todas las acciones ejecutadas por un usuario auditor/administrador.
     */
    @Query(value = "SELECT * FROM security_audit_logs WHERE performed_by = :performedBy ORDER BY timestamp DESC", nativeQuery = true)
    List<SecurityAuditLog> findByPerformedByNative(@Param("performedBy") String performedBy);

    /**
     * Consulta nativa para recuperar los últimos N eventos de seguridad del sistema.
     */
    @Query(value = "SELECT * FROM security_audit_logs ORDER BY timestamp DESC LIMIT :limit", nativeQuery = true)
    List<SecurityAuditLog> findRecentEventsNative(@Param("limit") int limit);
}
