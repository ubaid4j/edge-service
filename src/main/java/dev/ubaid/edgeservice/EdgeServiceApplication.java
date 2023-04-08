package dev.ubaid.edgeservice;

import dev.ubaid.edgeservice.EdgeServiceApplication.HttpMethodConversionRuntimeHints;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.http.HttpMethod;

@SpringBootApplication
@ConfigurationPropertiesScan
@ImportRuntimeHints(HttpMethodConversionRuntimeHints.class)
public class EdgeServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(EdgeServiceApplication.class, args);
	}

	/**
	 * @see <a href="https://github.com/spring-projects/spring-boot/issues/34483">spring-boot#issues/34483</a>
	 */
	static class HttpMethodConversionRuntimeHints implements RuntimeHintsRegistrar {
		@Override
		public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
			hints.reflection().registerType(HttpMethod.class, MemberCategory.INVOKE_PUBLIC_METHODS);
		}

	}

}
