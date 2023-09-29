package bg.stride.security.jwt.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class AuthenticationMetadata implements UserDetails {

    private String username;
    private String email;
    private String userRole;
    private String userId;
    private Set<StrideAuthority> authorities;

    private AuthenticationMetadata() {

    }

    private AuthenticationMetadata(
            String username,
            String email,
            String userRole,
            String userId,
            Set<StrideAuthority> authorities) {

        this.username = username;
        this.email = email;
        this.userRole = userRole;
        this.userId = userId;
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getUserRole() {
        return userRole;
    }

    public String getUserId() {
        return userId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public static AuthenticationMetadata.Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private String username;
        private String email;
        private String userRole;
        private String userId;
        private Set<StrideAuthority> authorities;

        private Builder() {
        }

        public Builder setUsername(String username) {
            this.username = username;
            return this;
        }

        public Builder setEmail(String email) {
            this.email = email;
            return this;
        }

        public Builder setUserRole(String userRole) {
            this.userRole = userRole;
            return this;
        }

        public Builder setUserId(String userId) {
            this.userId = userId;
            return this;
        }

        public Builder setAuthorities(Set<String> authorities) {
            Set<StrideAuthority> customAuthorities = new HashSet<>();
            for (String authority : authorities) {
                customAuthorities.add(new StrideAuthority(authority));
            }
            this.authorities = customAuthorities;
            return this;
        }

        public AuthenticationMetadata build() {

            return new AuthenticationMetadata(
                    this.username,
                    this.email,
                    this.userRole,
                    this.userId,
                    this.authorities
            );
        }
    }
}
