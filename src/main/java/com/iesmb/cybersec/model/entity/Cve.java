package com.iesmb.cybersec.model.entity;

import com.iesmb.cybersec.model.enums.Severity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "cves", indexes = {
        @Index(name = "idx_cve_code", columnList = "cve_code"),
        @Index(name = "idx_cve_severity", columnList = "severity")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Cve {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_code", nullable = false, unique = true, length = 30)
    private String cveCode; // Ej: CVE-2021-44228

    @Column(nullable = false, length = 200)
    private String title;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String description;

    @Column(name = "cvss_score")
    private Double cvssScore; // Ej: 9.8

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Severity severity;

    @Column(name = "published_date")
    private LocalDate publishedDate;

    @Column(name = "remediation_guide", columnDefinition = "TEXT")
    private String remediationGuide;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
}
