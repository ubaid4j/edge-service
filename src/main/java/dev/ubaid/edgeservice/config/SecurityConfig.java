package dev.ubaid.edgeservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

@Configuration
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
        // TODO: 5/3/23 make csrf good 
        CookieServerCsrfTokenRepository tokenRepository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
        XorServerCsrfTokenRequestAttributeHandler delegate = new XorServerCsrfTokenRequestAttributeHandler();
        // Use only the handle() method of XorServerCsrfTokenRequestAttributeHandler and the
        // default implementation of resolveCsrfTokenValue() from ServerCsrfTokenRequestHandler
        ServerCsrfTokenRequestHandler requestHandler = delegate::handle;

        return http
            .authorizeExchange(AUTHORIZE_EXCHANGE)
            .oauth2Login(Customizer.withDefaults())
            .exceptionHandling(EXCEPTION_HANDLING)
            .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler()))
            .csrf((csrf) -> csrf.csrfTokenRepository(tokenRepository).csrfTokenRequestHandler(requestHandler))
            .build();
    }

    private ServerLogoutSuccessHandler oidcLogoutSuccessHandler() {
        var oidcLogoutSuccessHandler =
            new OidcClientInitiatedServerLogoutSuccessHandler(repo);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
        return oidcLogoutSuccessHandler;
    }

    @Bean
    WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {
            Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
            return csrfToken.doOnSuccess(token -> {
                /* Ensures the token is subscribed to. */
            }).then(chain.filter(exchange));
        };
    }}
