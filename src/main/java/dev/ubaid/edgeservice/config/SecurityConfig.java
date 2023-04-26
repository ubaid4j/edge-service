package dev.ubaid.edgeservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.ExceptionHandlingSpec;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;

@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String[] STATIC_RESOURCES_PATH = {"/", "/*.css", "/*.js", "/favicon.ico"};
    private static final Customizer<AuthorizeExchangeSpec> AUTHORIZE_EXCHANGE = (spec) -> spec
        .pathMatchers(STATIC_RESOURCES_PATH).permitAll()
        .pathMatchers(HttpMethod.GET, "/books/**").permitAll()
        .anyExchange()
        .authenticated();
    private static final Customizer<ExceptionHandlingSpec> EXCEPTION_HANDLING = (spec) -> spec
        .authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED));

    private final ReactiveClientRegistrationRepository repo;

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange(AUTHORIZE_EXCHANGE)
            .oauth2Login(Customizer.withDefaults())
            .exceptionHandling(EXCEPTION_HANDLING)
            .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler()))
            .build();
    }

    private ServerLogoutSuccessHandler oidcLogoutSuccessHandler() {
        var oidcLogoutSuccessHandler =
            new OidcClientInitiatedServerLogoutSuccessHandler(repo);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
        return oidcLogoutSuccessHandler;
    }
}
