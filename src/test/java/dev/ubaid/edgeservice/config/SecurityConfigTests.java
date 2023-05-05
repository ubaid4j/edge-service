package dev.ubaid.edgeservice.config;

import static org.mockito.Mockito.when;

import dev.ubaid.edgeservice.web.UserController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

@WebFluxTest(value = UserController.class)
@Import(value = {SecurityConfig.class})
public class SecurityConfigTests {

    @Autowired
    WebTestClient webTestClient;

    @MockBean
    ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Test
    void whenLogoutAuthenticatedAndWithCsrfTokenThen302() {
        when(clientRegistrationRepository.findByRegistrationId("test"))
            .thenReturn(Mono.just(testClientRegistration()));

        webTestClient
            .mutateWith(SecurityMockServerConfigurers.mockOidcLogin())
            .mutateWith(SecurityMockServerConfigurers.csrf())
            .post()
            .uri("/logout")
            .exchange()
            .expectStatus()
            .isFound();
    }

    private ClientRegistration testClientRegistration() {
        return ClientRegistration.withRegistrationId("test")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .clientId("test")
            .tokenUri("https://sso.polarbookshop.com/token")
            .authorizationUri("https://sso.polarbookshop.com/auth")
            .redirectUri("https://polarbookshop.com")
            .build();
    }
}
