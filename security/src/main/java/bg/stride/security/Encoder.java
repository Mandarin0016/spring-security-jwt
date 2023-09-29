package bg.stride.security;

import org.springframework.security.core.userdetails.UserDetails;

public interface Encoder<T extends UserDetails> {

    String encode(T data);
}
