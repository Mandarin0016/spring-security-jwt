package bg.stride.security.jwt.provider;

import bg.stride.security.jwt.AuthenticationJwtDecoder;
import bg.stride.security.jwt.auth.JwtAuthentication;
import bg.stride.security.jwt.excpetion.InvalidBearerTokenException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class AuthenticationJwtProvider implements AuthenticationProvider {

    private static final List<Class<?>> SUPPORTED_AUTHENTICATIONS = List.of(
            JwtAuthentication.class
    );

    private final AuthenticationJwtDecoder decoder;

    public AuthenticationJwtProvider(AuthenticationJwtDecoder decoder) {
        this.decoder = decoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        JwtAuthentication jwtAuthentication = (JwtAuthentication) authentication;
        String jwt = jwtAuthentication.getJwt();

        try {
            decoder.decode(jwt);
            authentication.setAuthenticated(true);
        } catch (InvalidBearerTokenException e) {
            throw new RuntimeException(e);
        }


        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SUPPORTED_AUTHENTICATIONS.contains(authentication);
    }
}
