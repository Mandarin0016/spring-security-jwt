package bg.stride.security.jwt;

import bg.stride.security.Decoder;
import bg.stride.security.jwt.auth.AuthenticationMetadata;
import bg.stride.security.jwt.excpetion.InvalidBearerTokenException;
import bg.stride.security.jwt.verifier.AuthenticationJwtClaimsVerifier;
import bg.stride.security.jwt.verifier.AuthenticationJwtSignatureVerifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.text.ParseException;
import java.util.*;

@Component
public class AuthenticationJwtDecoder implements Decoder<AuthenticationMetadata> {

    private static final String BEARER_PREFIX = "Bearer ";
    private final ObjectMapper objectMapper;
    private final AuthenticationJwtClaimsVerifier<SecurityContext> claimsVerifier;
    private final AuthenticationJwtSignatureVerifier signatureVerifier;

    @Autowired
    public AuthenticationJwtDecoder(AuthenticationJwtSignatureVerifier signatureVerifier) {
        this.signatureVerifier = signatureVerifier;
        this.claimsVerifier = new AuthenticationJwtClaimsVerifier<>();
        this.objectMapper = new ObjectMapper();
    }
    public AuthenticationMetadata decode(String token) throws InvalidBearerTokenException {

        try {
            if (!StringUtils.hasLength(token)) {
                throw new InvalidBearerTokenException("Missing token");
            } else if (!token.startsWith(BEARER_PREFIX)) {
                throw new InvalidBearerTokenException("Token not formatted correctly");
            } else {
                String jwtString = token.substring("Bearer ".length());

                if (!StringUtils.hasLength(jwtString)){
                    throw new InvalidBearerTokenException("Missing token");
                }

                SignedJWT signedJWT = SignedJWT.parse(jwtString);
                JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
                claimsVerifier.verify(claims, null);
                signatureVerifier.verify(signedJWT);
                return this.extractMetadata(claims);
            }
        } catch (ParseException | BadJWTException e) {
            throw new RuntimeException(e);
        }
    }

    private AuthenticationMetadata extractMetadata(JWTClaimsSet claims) throws InvalidBearerTokenException {

        JsonNode tokenData = this.tryParseTokenData(claims);
        this.validateTokenData(tokenData);

        try {

            String username = tokenData.get("username").asText();
            String email = tokenData.get("email").asText();
            String userRole = tokenData.get("userRole").asText();
            String userId = tokenData.get("userId").asText();
            Set<String> authorities = new HashSet<>();
            Iterator<JsonNode> authoritiesItr = tokenData.get("authorities").iterator();
            while (authoritiesItr.hasNext()){
                String role = authoritiesItr.next().get("role").asText();
                authorities.add(role);
            }


            return AuthenticationMetadata.builder()
                    .setUsername(username)
                    .setEmail(email)
                    .setUserRole(userRole)
                    .setUserId(userId)
                    .setAuthorities(authorities)
                    .build();
        } catch (Exception var21) {
            throw new InvalidBearerTokenException("Couldn't parse JWT data", var21);
        }
    }

    private void validateTokenData(JsonNode tokenData) throws InvalidBearerTokenException {

        if (tokenData == null || tokenData.isNull()) {
            throw new InvalidBearerTokenException("No data object in JWT");
        }
    }

    private JsonNode tryParseTokenData(JWTClaimsSet claims) throws InvalidBearerTokenException {

        try {
            return objectMapper.readTree(claims.getClaim("data").toString());
        } catch (IOException var3) {
            throw new InvalidBearerTokenException("Couldn't parse data", var3);
        }
    }
}
