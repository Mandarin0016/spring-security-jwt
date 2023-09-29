package bg.stride.security.jwt.auth;

import org.springframework.security.core.GrantedAuthority;

public class StrideAuthority implements GrantedAuthority {
    private String role;

    public StrideAuthority(String role) {
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return this.role;
    }

    @Override
    public String toString() {
        return this.role;
    }
}
