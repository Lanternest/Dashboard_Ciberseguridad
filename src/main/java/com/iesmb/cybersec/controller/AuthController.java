package com.iesmb.cybersec.controller;

import com.iesmb.cybersec.dto.request.LoginRequest;
import com.iesmb.cybersec.dto.request.RegisterRequest;
import com.iesmb.cybersec.dto.response.ApiMessageResponse;
import com.iesmb.cybersec.dto.response.AuthResponse;
import com.iesmb.cybersec.model.entity.User;
import com.iesmb.cybersec.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Tag(name = "1. Autenticación & Seguridad JWT", description = "Endpoints de login y registro. Emisión de tokens JWT con vida útil muy corta.")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "Iniciar sesión y obtener token JWT de corta vida útil",
            description = "Devuelve un token JWT con vida útil reducida (por defecto 5 minutos) debido a la sensibilidad del acceso.")
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        AuthResponse response = authService.login(loginRequest, request);
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "Registrar nuevo usuario con privilegios (ADMIN, AUDITOR, OPERATOR)")
    @PostMapping("/register")
    public ResponseEntity<ApiMessageResponse> register(@Valid @RequestBody RegisterRequest registerRequest, HttpServletRequest request) {
        User user = authService.register(registerRequest, request);
        return new ResponseEntity<>(
                ApiMessageResponse.builder()
                        .success(true)
                        .message("Usuario '" + user.getUsername() + "' registrado exitosamente con rol " + user.getRole().name())
                        .build(),
                HttpStatus.CREATED
        );
    }

    @Operation(summary = "Consultar identidad del usuario actual autenticado")
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities()
        ));
    }
}
