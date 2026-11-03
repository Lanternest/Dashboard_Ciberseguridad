package com.iesmb.cybersec.repository;

import com.iesmb.cybersec.model.entity.Cve;
import com.iesmb.cybersec.model.enums.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CveRepository extends JpaRepository<Cve, Long> {

    Optional<Cve> findByCveCode(String cveCode);

    boolean existsByCveCode(String cveCode);

    List<Cve> findBySeverity(Severity severity);

    @Query(value = "SELECT * FROM cves WHERE severity = :severity ORDER BY cvss_score DESC", nativeQuery = true)
    List<Cve> findBySeverityNative(@Param("severity") String severity);

    @Query(value = "SELECT * FROM cves WHERE cvss_score >= :minScore ORDER BY cvss_score DESC", nativeQuery = true)
    List<Cve> findByMinCvssScoreNative(@Param("minScore") Double minScore);
}
