package com.iesmb.cybersec.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.iesmb.cybersec.model.enums.Environment;
import com.iesmb.cybersec.model.enums.ServerStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "servers", indexes = {
        @Index(name = "idx_server_hostname", columnList = "hostname"),
        @Index(name = "idx_server_ip", columnList = "ip_address"),
        @Index(name = "idx_server_exposed", columnList = "is_exposed"),
        @Index(name = "idx_server_outdated", columnList = "is_outdated_os")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ServerAsset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String hostname;

    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    @Column(length = 20)
    private String macAddress;

    @Column(name = "operating_system", nullable = false, length = 50)
    private String operatingSystem;

    @Column(name = "os_version", nullable = false, length = 50)
    private String osVersion;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Environment environment;

    @Column(name = "is_exposed", nullable = false)
    @Builder.Default
    private boolean isExposed = false;

    @Column(name = "is_outdated_os", nullable = false)
    @Builder.Default
    private boolean isOutdatedOs = false;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private ServerStatus status = ServerStatus.ONLINE;

    @Column(length = 100)
    private String location;

    @Column(columnDefinition = "TEXT")
    private String description;

    @OneToMany(mappedBy = "server", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnoreProperties("server")
    @Builder.Default
    private List<VulnerabilityFinding> findings = new ArrayList<>();

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
