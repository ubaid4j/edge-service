package dev.ubaid.edgeservice.web;

import dev.ubaid.edgeservice.user.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("user")
public class UserController {

    @GetMapping
    public Mono<User> getUser() {
        return ReactiveSecurityContextHolder
            .getContext()
            .map(SecurityContext::getAuthentication)
            .map(Authentication::getPrincipal)
            .cast(OidcUser.class)
            .map(User::from);
    }

    @GetMapping("v2")
    public Mono<User> getUser2(@AuthenticationPrincipal OidcUser oidcUser) {
        return Mono.just(User.from(oidcUser));
    }

    @GetMapping("oidc")
    public Mono<OidcUser> getOIdcUser(@AuthenticationPrincipal OidcUser oidcUser) {
        return Mono.just(oidcUser);
    }
}
