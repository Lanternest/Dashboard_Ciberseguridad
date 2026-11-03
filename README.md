# Dashboard de Auditoría y Reportes de Ciberseguridad

Una API REST orientada a la administración de sistemas e infraestructura corporativa para:
- **Registrar servidores de una red**: Hostnames, direcciones IP (IPv4/IPv6), sistemas operativos, versiones, estado de exposición perimetral y entornos.
- **Centralizar escaneos de vulnerabilidades**: Integración con herramientas de escaneo (Nessus, OpenVAS, Trivy, scripts de red).
- **Mapear CVEs**: Catálogo de vulnerabilidades y exposiciones comunes (Common Vulnerabilities and Exposures) con puntajes CVSS y guías de remediación.
- **Auditoría Forense en MySQL**: Trazabilidad completa de quién reportó una vulnerabilidad, fecha/hora exacta, cuándo y quién la mitigó, y registro obligatorio de la dirección IP de origen de cada operación.

---

## 🛡️ Arquitectura y Cumplimiento de Requerimientos

### 1. Spring Security 6 + JWT (Vida Útil Muy Corta)
- **Autenticación Forzada en Todos los Endpoints**:
  - Toda petición a la API (excepto `/api/auth/login`, `/api/auth/register` y la documentación Swagger) requiere obligatoriamente un token JWT válido transmitido en el encabezado `Authorization: Bearer <token>`.
  - Si una petición no incluye token o el token no es válido, `JwtAuthenticationEntryPoint` intercepta la petición y responde con código HTTP `401 Unauthorized` en formato JSON estándar.
- **Expiración de Corta Vida Útil (`expiration-ms`)**:
  - En entornos de ciberseguridad y administración de servidores, los tokens de larga duración representan un vector de riesgo crítico de secuestro de sesión y replay attacks.
  - Se configuró por defecto una vigencia estricta de **5 minutos (300.000 ms)** mediante la propiedad `security.jwt.expiration-ms` en `application.properties`.
  - El endpoint de autenticación devuelve el campo `expiresInSeconds: 300` para que el cliente conozca la vigencia exacta.
- **Control de Acceso Basado en Roles (RBAC)**:
  - `ROLE_ADMIN`: Control total de servidores, CVEs, usuarios, mitigación y logs forenses.
  - `ROLE_AUDITOR`: Registro de CVEs, reporte de hallazgos y consulta de auditorías.
  - `ROLE_OPERATOR`: Monitoreo de activos, reporte y remediación de hallazgos.

---

### 2. Spring Data JPA: Consultas Nativas (`@Query(nativeQuery = true)`)
Se implementaron consultas nativas en MySQL para garantizar máximo rendimiento al filtrar y correlacionar activos críticos:

1. **Filtrado rápido de activos de red expuestos a internet**:
   ```sql
   SELECT s.* FROM servers s WHERE s.is_exposed = 1 ORDER BY s.hostname ASC
   ```
   *Endpoint:* `GET /api/servers/exposed`

2. **Filtrado rápido de sistemas operativos desactualizados u obsoletos**:
   ```sql
   SELECT s.* FROM servers s WHERE s.is_outdated_os = 1 ORDER BY s.operating_system ASC, s.os_version ASC
   ```
   *Endpoint:* `GET /api/servers/outdated-os`

3. **Filtrado de riesgo crítico combinado (Expuesto + SO Desactualizado)**:
   ```sql
   SELECT s.* FROM servers s WHERE s.is_exposed = 1 AND s.is_outdated_os = 1 ORDER BY s.hostname ASC
   ```
   *Endpoint:* `GET /api/servers/exposed-and-outdated`

4. **Filtrado complejo: Servidores expuestos con vulnerabilidades CRÍTICAS activas**:
   ```sql
   SELECT DISTINCT s.* FROM servers s
   INNER JOIN vulnerability_findings vf ON s.id = vf.server_id
   INNER JOIN cves c ON vf.cve_id = c.id
   WHERE s.is_exposed = 1 AND c.severity = 'CRITICAL' AND vf.status = 'DETECTED'
   ORDER BY s.hostname ASC
   ```
   *Endpoint:* `GET /api/servers/critical-risk`

5. **Distribución agregada de sistemas operativos en la infraestructura**:
   ```sql
   SELECT operating_system AS osName, COUNT(*) AS count FROM servers GROUP BY operating_system ORDER BY count DESC
   ```

---

### 3. MySQL: Estructuración de Tablas de Auditoría
El esquema de base de datos (`cybersec_dashboard_db`) estructura la auditoría en dos niveles:

#### Nivel 1: Auditoría en el Hallazgo de Vulnerabilidad (`vulnerability_findings`)
Cada vulnerabilidad registrada en un servidor almacena de forma inmutable:
- `reported_by`: Nombre de usuario del auditor u operador que cargó el hallazgo.
- `reported_at`: Marca temporal exacta (`DATETIME(6)`) del reporte.
- `reporter_ip`: Dirección IP de origen del cliente (extraída de `X-Forwarded-For` o conexión directa mediante `ClientIpUtil`).
- `mitigated_by`: Usuario que ejecutó o validó la solución técnica.
- `mitigated_at`: Fecha y hora exacta de la mitigación.
- `mitigator_ip`: Dirección IP desde la cual se confirmó la mitigación.
- `mitigation_notes`: Bitácora técnica con las acciones de remediación aplicadas (parches, reglas de firewall, reversión de librerías).

#### Nivel 2: Registro Central de Eventos Forenses (`security_audit_logs`)
Tabla dedicada para registrar todo evento crítico del sistema:
- `event_type`: (ej. `USER_LOGIN_SUCCESS`, `USER_LOGIN_FAILED`, `SERVER_REGISTERED`, `VULNERABILITY_REPORTED`, `VULNERABILITY_MITIGATED`).
- `action`: Descripción legible del evento.
- `performed_by`: Usuario que ejecutó la acción.
- `source_ip`: Dirección IP de origen.
- `target_entity` y `target_id`: Entidad y registro afectado.
- `details`: Detalle técnico o cambios de parámetros.
- `timestamp`: Marca temporal del evento.

---

## 🚀 Requisitos del Entorno & Puesta en Marcha

- **Java**: 21 LTS
- **Motor de Base de Datos**: MySQL 8.x / MariaDB (puerto 3306)
- **Maven**: Incluido a través de Maven Wrapper (`mvnw` / `mvnw.cmd`)

### Conexión a Base de Datos
En `src/main/resources/application.properties`:
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/cybersec_dashboard_db?createDatabaseIfNotExist=true&useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true
spring.datasource.username=root
spring.datasource.password=
```

### Ejecutar la Aplicación
```powershell
.\mvnw.cmd spring-boot:run
```

Al iniciar por primera vez, el componente `DataInitializer` sembrará automáticamente:
- **Usuarios de prueba**:
  - `admin` / `Admin123!` (`ROLE_ADMIN`)
  - `auditor` / `Auditor123!` (`ROLE_AUDITOR`)
  - `operator` / `Operator123!` (`ROLE_OPERATOR`)
- **CVEs críticos reales**: `CVE-2021-44228` (Log4Shell), `CVE-2017-0144` (EternalBlue), `CVE-2024-3094` (XZ Utils), `CVE-2023-44487` (HTTP/2 Rapid Reset), `CVE-2023-22515` (Confluence).
- **Servidores de red**: Públicos, privados, sistemas desactualizados (Windows Server 2008 R2, CentOS 7) y actualizados (Ubuntu 22.04, Debian 12).
- **Hallazgos y auditorías previas**.

---

## 📖 Documentación Interactiva Swagger / OpenAPI

Con la aplicación en ejecución, acceda en su navegador a:
👉 **[http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)**

### ¿Cómo probar desde Swagger UI?
1. Diríjase a **1. Autenticación & Seguridad JWT** -> `POST /api/auth/login`.
2. Inicie sesión con `admin` y `Admin123!`.
3. Copie el token del campo `token`.
4. Haga clic en el botón superior verde **Authorize 🔓** y pegue el token.
5. Ahora todos los endpoints protegidos ejecutarán las peticiones autenticadas.

---

## 🧪 Pruebas Automatizadas

Para ejecutar la suite de pruebas unitarias y de integración:
```powershell
.\mvnw.cmd test
```
Resultados de las pruebas:
- `AuthControllerIntegrationTest`: Valida rechazo 401 en accesos sin token, autenticación con JWT de corta vida útil (300s) y rechazo de contraseñas inválidas.
- `NativeQueryRepositoriesTest`: Valida consultas nativas (`findExposedServersNative`, `findOutdatedOsServersNative`, `findExposedAndOutdatedServersNative`, `countServersByOsNative`), campos de auditoría (`reported_by`, `mitigated_by`, `source_ip`) y logs forenses.

---

## 📡 Colección de Peticiones HTTP

Se incluye el archivo [cybersecurity-api.http](file:///c:/Users/emanu/Documents/IESMB/Tercer%20a%C3%B1o/Programaci%C3%B3n%20III/Final/cybersecurity-api.http) con 22 peticiones preconfiguradas para probar la API con las extensiones **REST Client** de VS Code o el cliente HTTP de IntelliJ IDEA.
