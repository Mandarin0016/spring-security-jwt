package bg.stride.security.jwt.filter;

import bg.stride.security.jwt.auth.JwtAuthentication;
import bg.stride.security.jwt.manager.AuthenticationJwtManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.ServletException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@Component
public class AuthenticationJwtFilter extends OncePerRequestFilter {

    private final AuthenticationJwtManager authenticationJwtManager;

    public AuthenticationJwtFilter(AuthenticationJwtManager authenticationJwtManager) {
        this.authenticationJwtManager = authenticationJwtManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String jwt = request.getHeader("Authorization");

        if (jwt != null) {
            JwtAuthentication jwtAuthentication = new JwtAuthentication(jwt);
            Authentication authentication = authenticationJwtManager.authenticate(jwtAuthentication);
            if (authentication.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }

}
