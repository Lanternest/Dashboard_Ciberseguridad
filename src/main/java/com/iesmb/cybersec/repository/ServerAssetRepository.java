package com.iesmb.cybersec.repository;

import com.iesmb.cybersec.dto.projection.OsCountProjection;
import com.iesmb.cybersec.model.entity.ServerAsset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ServerAssetRepository extends JpaRepository<ServerAsset, Long> {

    Optional<ServerAsset> findByHostname(String hostname);

    Optional<ServerAsset> findByIpAddress(String ipAddress);

    boolean existsByHostname(String hostname);

    boolean existsByIpAddress(String ipAddress);

    // =========================================================================
    // CONSULTAS NATIVAS (@Query nativeQuery = true) - EXIGIDAS EN REQUERIMIENTOS
    // =========================================================================

    /**
     * Consulta nativa optimizada para filtrar rápidamente activos de red expuestos a internet/red pública.
     */
    @Query(value = "SELECT s.* FROM servers s WHERE s.is_exposed = 1 ORDER BY s.hostname ASC", nativeQuery = true)
    List<ServerAsset> findExposedServersNative();

    /**
     * Consulta nativa para filtrar rápidamente servidores con sistemas operativos desactualizados o fuera de soporte.
     */
    @Query(value = "SELECT s.* FROM servers s WHERE s.is_outdated_os = 1 ORDER BY s.operating_system ASC, s.os_version ASC", nativeQuery = true)
    List<ServerAsset> findOutdatedOsServersNative();

    /**
     * Consulta nativa de alto riesgo: servidores expuestos que a la vez poseen sistema operativo desactualizado.
     */
    @Query(value = "SELECT s.* FROM servers s WHERE s.is_exposed = 1 AND s.is_outdated_os = 1 ORDER BY s.hostname ASC", nativeQuery = true)
    List<ServerAsset> findExposedAndOutdatedServersNative();

    /**
     * Consulta nativa compleja: servidores expuestos que tienen vulnerabilidades críticas activas no mitigadas.
     */
    @Query(value = "SELECT DISTINCT s.* FROM servers s " +
                   "INNER JOIN vulnerability_findings vf ON s.id = vf.server_id " +
                   "INNER JOIN cves c ON vf.cve_id = c.id " +
                   "WHERE s.is_exposed = 1 AND c.severity = 'CRITICAL' AND vf.status = 'DETECTED' " +
                   "ORDER BY s.hostname ASC", nativeQuery = true)
    List<ServerAsset> findExposedServersWithCriticalVulnerabilitiesNative();

    /**
     * Consulta nativa para distribución y agregación de sistemas operativos en la red.
     */
    @Query(value = "SELECT operating_system AS osName, COUNT(*) AS count FROM servers GROUP BY operating_system ORDER BY count DESC", nativeQuery = true)
    List<OsCountProjection> countServersByOsNative();

    /**
     * Búsqueda por rango o subred mediante consulta nativa.
     */
    @Query(value = "SELECT s.* FROM servers s WHERE s.ip_address LIKE CONCAT(:ipPrefix, '%') ORDER BY s.ip_address ASC", nativeQuery = true)
    List<ServerAsset> findByIpSubnetNative(@Param("ipPrefix") String ipPrefix);
}
