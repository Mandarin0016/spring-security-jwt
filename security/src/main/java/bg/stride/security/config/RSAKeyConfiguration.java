package bg.stride.security.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RSAKeyConfiguration {

    public static final String PRIVATE_KEY_ID = "JsmDAJGHY/JJFZ4OCgpxMMVt+Ur+EdRMPrqgoRAF9/I=";

    @Bean("privateJWK")
    public RSAKey rsaPrivateJWK() throws JOSEException {
        return new RSAKeyGenerator(2048).keyID(PRIVATE_KEY_ID).generate();
    }

    @Bean("publicJWK")
    public RSAKey rsaPublicJWK(@Qualifier("privateJWK") RSAKey privateJWK)  {
        return privateJWK.toPublicJWK();
    }
}
