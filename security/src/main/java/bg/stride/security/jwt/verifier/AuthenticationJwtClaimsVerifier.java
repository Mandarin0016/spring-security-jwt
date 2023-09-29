package bg.stride.security.jwt.verifier;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import net.jcip.annotations.ThreadSafe;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static bg.stride.security.jwt.AuthenticationJwtEncoder.AUTHOR_JWT_CLAIM;
import static bg.stride.security.jwt.AuthenticationJwtEncoder.VERSION_JWT_CLAIM;

@ThreadSafe
@Component
public final class AuthenticationJwtClaimsVerifier<C extends SecurityContext> extends DefaultJWTClaimsVerifier<C> {

    private static final JWTClaimsSet EXACT_MATCH_CLAIMS = (new JWTClaimsSet.Builder())
            .issuer("stride")
            .claim("author", AUTHOR_JWT_CLAIM)
            .claim("version", VERSION_JWT_CLAIM)
            .build();
    private static final Set<String> REQUIRED_CLAIMS = new HashSet(Arrays.asList("data"));

    public AuthenticationJwtClaimsVerifier() {
        super(EXACT_MATCH_CLAIMS, REQUIRED_CLAIMS);
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, C context) throws BadJWTException {
        super.verify(claimsSet, context);
    }
}