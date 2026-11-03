package com.iesmb.cybersec.dto.response;

import com.iesmb.cybersec.model.enums.Severity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CveResponse {

    private Long id;
    private String cveCode;
    private String title;
    private String description;
    private Double cvssScore;
    private Severity severity;
    private LocalDate publishedDate;
    private String remediationGuide;
}
