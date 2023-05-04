package dev.ubaid.edgeservice.web;

import dev.ubaid.edgeservice.config.SecurityConfig;
import dev.ubaid.edgeservice.user.User;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.web.reactive.server.WebTestClient;

@WebFluxTest(UserController.class)
@Import(SecurityConfig.class)
class UserControllerTest {

    @Autowired
    WebTestClient webTestClient;

    @MockBean
    ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Test
    void whenNotAuthenticatedThen401() {
        webTestClient
            .get()
            .uri("/user")
            .exchange()
            .expectStatus()
            .isUnauthorized();
    }

    @Test
    void whenAuthenticatedThenReturnUser() {
        var expectedUser = new User("jon.snow", "Jon", "Snow", List.of("employee", "customer"));

        webTestClient
            .mutateWith(configureMockOidcLogin(expectedUser))
            .get()
            .uri("/user")
            .exchange()
            .expectStatus()
            .is2xxSuccessful()
            .expectBody(User.class)
            .value(user -> Assertions.assertEquals(expectedUser, user));
    }

    private SecurityMockServerConfigurers.OidcLoginMutator configureMockOidcLogin(User expectedUser) {
        Consumer<OidcIdToken.Builder> idToken = builder -> {
            builder.claim(StandardClaimNames.PREFERRED_USERNAME, expectedUser.username());
            builder.claim(StandardClaimNames.GIVEN_NAME, expectedUser.firstName());
            builder.claim(StandardClaimNames.FAMILY_NAME, expectedUser.lastName());
        };
        return SecurityMockServerConfigurers.mockOidcLogin().idToken(idToken);
    }
}
