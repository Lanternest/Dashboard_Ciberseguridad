package com.iesmb.cybersec.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MitigateFindingRequest {

    @NotBlank(message = "Las notas o descripción de la mitigación aplicada son obligatorias para el registro de auditoría")
    private String mitigationNotes;
}
