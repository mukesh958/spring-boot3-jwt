package com.javatechie.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

@Configuration
public class SwaggerConfig {

    /**
     * http://localhost:8080/swagger-ui.html
     */
	@Bean
	public OpenAPI customOpenAPI() {
	    return new OpenAPI()
				.info(getInfo())
				.addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
				.components(new Components()
					.addSecuritySchemes("bearerAuth",
						new SecurityScheme()
							.type(SecurityScheme.Type.HTTP)
							.scheme("bearer")
							.bearerFormat("JWT")
						)
					)
					;
	}
	private Info getInfo() {
		Info info= new Info();
		info.version("1.0.0");
		info.title("Spring Boot Basic things.");
		info.description("This Application contains all the Rest end point that is needed for basic operation.");
		Contact contact= new Contact();
		contact.setEmail("Mukesh958@gmail.com");
		contact.setName("Mukesh Gupta");
		contact.setUrl("It's dummy");
		info.contact(contact);
		
		License license= new License();
		license.setName("Dummy name");
		license.setUrl("Dummy URL");
		info.license(license);
		
		
		return info;
	}
}