package dev.ubaid.edgeservice.web.filter;

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * This filter is responsible to add csrf token in response header as a cookie.
 */
@Component
public class CsrfCookieWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
        return csrfToken.doOnSuccess(token -> {
            /* Ensures the token is subscribed to. */
        }).then(chain.filter(exchange));
    }
}
