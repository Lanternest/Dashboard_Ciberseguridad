package com.iesmb.cybersec.service;

import com.iesmb.cybersec.dto.request.LoginRequest;
import com.iesmb.cybersec.dto.request.RegisterRequest;
import com.iesmb.cybersec.dto.response.AuthResponse;
import com.iesmb.cybersec.exception.BadRequestException;
import com.iesmb.cybersec.model.entity.User;
import com.iesmb.cybersec.model.enums.AuditEventType;
import com.iesmb.cybersec.repository.UserRepository;
import com.iesmb.cybersec.security.jwt.JwtTokenProvider;
import com.iesmb.cybersec.util.ClientIpUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final SecurityAuditLogService auditLogService;

    @Transactional
    public AuthResponse login(LoginRequest loginRequest, HttpServletRequest request) {
        String clientIp = ClientIpUtil.getClientIp(request);

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            String jwt = tokenProvider.generateToken(authentication);
            long expirationSeconds = tokenProvider.getExpirationMs() / 1000;

            String role = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .findFirst()
                    .orElse("ROLE_OPERATOR");

            // Registro de auditoría de autenticación exitosa
            auditLogService.logEvent(
                    AuditEventType.USER_LOGIN_SUCCESS,
                    "Autenticación exitosa en sistema y generación de token JWT de corta vida útil (" + expirationSeconds + "s)",
                    loginRequest.getUsername(),
                    clientIp,
                    "AUTH",
                    loginRequest.getUsername(),
                    "Rol autenticado: " + role
            );

            return AuthResponse.builder()
                    .token(jwt)
                    .tokenType("Bearer")
                    .expiresInSeconds(expirationSeconds)
                    .username(loginRequest.getUsername())
                    .role(role)
                    .message("Autenticación exitosa. Token válido por " + expirationSeconds + " segundos debido a la alta sensibilidad del acceso.")
                    .build();

        } catch (BadCredentialsException ex) {
            // Registro de auditoría de intento fallido (Alerta de seguridad)
            auditLogService.logEvent(
                    AuditEventType.USER_LOGIN_FAILED,
                    "Intento de inicio de sesión fallido con credenciales inválidas",
                    loginRequest.getUsername(),
                    clientIp,
                    "AUTH",
                    loginRequest.getUsername(),
                    "Contraseña incorrecta o usuario inexistente"
            );
            throw ex;
        }
    }

    @Transactional
    public User register(RegisterRequest registerRequest, HttpServletRequest request) {
        String clientIp = ClientIpUtil.getClientIp(request);

        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new BadRequestException("El nombre de usuario '" + registerRequest.getUsername() + "' ya está registrado");
        }

        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new BadRequestException("El correo electrónico '" + registerRequest.getEmail() + "' ya está registrado");
        }

        User user = User.builder()
                .username(registerRequest.getUsername())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .email(registerRequest.getEmail())
                .fullName(registerRequest.getFullName())
                .role(registerRequest.getRole())
                .enabled(true)
                .build();

        User savedUser = userRepository.save(user);

        auditLogService.logEvent(
                AuditEventType.USER_REGISTER,
                "Registro de nuevo usuario administrador/auditor en la plataforma",
                registerRequest.getUsername(),
                clientIp,
                "USER",
                String.valueOf(savedUser.getId()),
                "Rol asignado: " + registerRequest.getRole().name()
        );

        return savedUser;
    }
}
