package de.thb.webbaki.configuration.filter;

import de.thb.webbaki.service.TurnstileService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class TurnstileLoginFilter extends OncePerRequestFilter {

    private final TurnstileService turnstileService;
    private final AuthenticationFailureHandler failureHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        boolean isLoginPost = "POST".equalsIgnoreCase(request.getMethod())
                && (request.getRequestURI().equals(request.getContextPath() + "/login") || request.getRequestURI().equals(request.getContextPath() + "/register/user"));

        if (!isLoginPost || !turnstileService.getUse()) {
            chain.doFilter(request, response);
            return;
        }

        String token = request.getParameter("cf-turnstile-response");
        String clientIp = getClientIp(request);

        if (!turnstileService.validate(token, clientIp)) {
            failureHandler.onAuthenticationFailure(
                    request, response,
                    new org.springframework.security.core.AuthenticationException("Turnstile failed") {});
            return;
        }

        chain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        return (xf != null && !xf.isBlank()) ? xf.split(",")[0].trim() : request.getRemoteAddr();
    }
}
