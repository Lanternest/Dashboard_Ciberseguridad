package com.iesmb.cybersec.dto.request;

import com.iesmb.cybersec.model.enums.Severity;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CveRequest {

    @NotBlank(message = "El identificador CVE es obligatorio")
    @Pattern(regexp = "^CVE-\\d{4}-\\d{4,}$", message = "El código debe cumplir con el formato estándar CVE (ej: CVE-2021-44228)")
    private String cveCode;

    @NotBlank(message = "El título o resumen de la vulnerabilidad es obligatorio")
    private String title;

    @NotBlank(message = "La descripción técnica del CVE es obligatoria")
    private String description;

    @NotNull(message = "El puntaje CVSS es obligatorio")
    @DecimalMin(value = "0.0", message = "El puntaje CVSS mínimo es 0.0")
    @DecimalMax(value = "10.0", message = "El puntaje CVSS máximo es 10.0")
    private Double cvssScore;

    @NotNull(message = "La severidad es obligatoria (LOW, MEDIUM, HIGH, CRITICAL)")
    private Severity severity;

    private LocalDate publishedDate;

    private String remediationGuide;
}
