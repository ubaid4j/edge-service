package dev.ubaid.edgeservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.ExceptionHandlingSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.LogoutSpec;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final String[] STATIC_RESOURCES_PATH = {"/", "/*.css", "/*.js", "/favicon.ico"};
    private static final Customizer<AuthorizeExchangeSpec> AUTHORIZE_EXCHANGE = (spec) -> spec
        .pathMatchers(STATIC_RESOURCES_PATH).permitAll()
        .pathMatchers(HttpMethod.GET, "/api/books/**").permitAll()
        .pathMatchers(HttpMethod.GET, "/management/health/**").permitAll()
        .anyExchange()
        .authenticated();
    private static final Customizer<ExceptionHandlingSpec> EXCEPTION_HANDLING = (spec) -> spec
        .authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED));

    private static final Customizer<CsrfSpec> CSRF = csrfSpec -> {
        CookieServerCsrfTokenRepository tokenRepository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
        XorServerCsrfTokenRequestAttributeHandler delegate = new XorServerCsrfTokenRequestAttributeHandler();
        // Use only the handle() method of XorServerCsrfTokenRequestAttributeHandler and the
        // default implementation of resolveCsrfTokenValue() from ServerCsrfTokenRequestHandler
        ServerCsrfTokenRequestHandler requestHandler = delegate::handle;
        csrfSpec.csrfTokenRepository(tokenRepository).csrfTokenRequestHandler(requestHandler);
    };

    private final Customizer<LogoutSpec> logout;

    public SecurityConfig(ReactiveClientRegistrationRepository repo) {
        logout = logoutSpec -> {
            var oidcLogoutSuccessHandler =
                new OidcClientInitiatedServerLogoutSuccessHandler(repo);
            oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
            logoutSpec.logoutSuccessHandler(oidcLogoutSuccessHandler);
        };
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange(AUTHORIZE_EXCHANGE)
            .oauth2Login(Customizer.withDefaults())
            .exceptionHandling(EXCEPTION_HANDLING)
            .logout(logout)
            .csrf(CSRF)
            .oauth2ResourceServer(spec -> spec.jwt(Customizer.withDefaults()))
            .build();
    }

    @Bean
    ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }
}
