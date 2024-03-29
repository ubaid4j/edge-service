package dev.ubaid.edgeservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest(
	webEnvironment = WebEnvironment.RANDOM_PORT
)
@Testcontainers
class EdgeServiceApplicationTests {

	private static final int REDIS_PORT = 6379;

	@Container
	private static GenericContainer<?> redis =
		new GenericContainer<>(DockerImageName.parse("redis:latest"))
			.withExposedPorts(REDIS_PORT);

	@DynamicPropertySource
	private static void redisProps(DynamicPropertyRegistry registry) {
		registry.add("spring.data.redis.host", () -> redis.getHost());;
		registry.add("spring.data.redis.port", () -> redis.getMappedPort(REDIS_PORT));
	}

	@MockBean
	ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;
	
	@MockBean
	ReactiveJwtDecoder reactiveJwtDecoder;

	@Test
	void contextLoads() {
	}

}
