package bg.stride.security.jwt.verifier;

import bg.stride.security.jwt.excpetion.InvalidBearerTokenException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import net.jcip.annotations.ThreadSafe;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;


@ThreadSafe
@Component
public class AuthenticationJwtSignatureVerifier {

    private final JWSVerifier jwsVerifier;

    public AuthenticationJwtSignatureVerifier(@Qualifier("publicJWK") RSAKey rsaPublicJWK) throws JOSEException {
        this.jwsVerifier = new RSASSAVerifier(rsaPublicJWK);
    }

    public void verify(SignedJWT jwt) throws InvalidBearerTokenException {

        try {
            boolean result = jwt.verify(jwsVerifier);

            if (!result){
                throw new InvalidBearerTokenException("The given token is not valid.");
            }
        } catch (JOSEException e) {
            throw new InvalidBearerTokenException("Can't verify token");
        }
    }
}
