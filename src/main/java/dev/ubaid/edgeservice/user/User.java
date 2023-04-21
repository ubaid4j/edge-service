package dev.ubaid.edgeservice.user;

import java.util.List;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public record User(
   String username,
   String firstName,
   String lastName,
   List<String> roles
) {
    public static User from(OidcUser oidcUser) {
        return new User (
          oidcUser.getPreferredUsername(),
          oidcUser.getGivenName(),
          oidcUser.getFamilyName(),
          List.of("employee", "customer")
        );
    }
}
