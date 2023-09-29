package bg.stride.security.jwt;

import bg.stride.security.Encoder;
import bg.stride.security.jwt.auth.AuthenticationMetadata;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.nimbusds.jose.JWSAlgorithm.RS256;


@Component
public class AuthenticationJwtEncoder implements Encoder<AuthenticationMetadata> {

    public static final JWSAlgorithm EXPECTED_ALGORITHM = RS256;
    public static final String AUTHOR_JWT_CLAIM = "stride";
    public static final String VERSION_JWT_CLAIM = "1";
    private final JWSSigner signer;

    public AuthenticationJwtEncoder(@Qualifier("privateJWK") RSAKey rsaPrivateJWK) throws JOSEException {
        this.signer = new RSASSASigner(rsaPrivateJWK);
    }

    @Override
    public String encode(AuthenticationMetadata data) {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(data.getEmail())
                .issuer("stride")
                .expirationTime(new Date(new Date().getTime() + 60 * 100000))
                .claim("data", data)
                .claim("authorities", data.getAuthorities().stream().map(Objects::toString).collect(Collectors.joining(",")))
                .claim("author", AUTHOR_JWT_CLAIM)
                .claim("version", VERSION_JWT_CLAIM)
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(EXPECTED_ALGORITHM)
                        .type(JOSEObjectType.JWT)
                        .build(),
                claimsSet);

        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return signedJWT.serialize();
    }
}
