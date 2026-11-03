package com.iesmb.cybersec.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI cybersecurityDashboardOpenAPI() {
        final String securitySchemeName = "BearerAuth";

        return new OpenAPI()
                .info(new Info()
                        .title("Dashboard de Auditoría y Reportes de Ciberseguridad API")
                        .description("API REST orientada a la administración de infraestructura de red, registro de servidores, mapeo de CVEs, auditoría de eventos y escaneos de vulnerabilidades con tokens JWT de corta vida útil.")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Equipo de Ciberseguridad & SysAdmin")
                                .email("security-admin@iesmb.edu.ar"))
                        .license(new License().name("Apache 2.0")))
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(new Components()
                        .addSecuritySchemes(securitySchemeName,
                                new SecurityScheme()
                                        .name(securitySchemeName)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Ingrese su token JWT de corta vida útil (ej: generado en /api/auth/login)")));
    }
}
