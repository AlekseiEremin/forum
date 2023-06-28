package telran.java47.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class AuthorizationConfiguration {
	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.httpBasic(withDefaults());
		http.csrf().disable();//отключает 
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);//отмена куков
		http.authorizeRequests(authrize -> authrize
				.mvcMatchers("/account/register","/forum/posts/**")
				    .permitAll()//разреши всем если совмадает то что находится в .mvcMatchers()
				.mvcMatchers("/account/login","/account/user/**","/forum/post/**")
			   	    .access("@customSecurity.checkPasswordTime(authentication.name)")
			    .mvcMatchers("/account/user/{login}/role/{role}")
				     .hasRole("ADMINISTRATOR")//аутефецыровонный и имеет роль 
				.mvcMatchers(HttpMethod.PUT, "/account/user/{login}")
				     .access("#login == authentication.name")//тут получается если логин равен аутефицыровоному юзеру 
				.mvcMatchers(HttpMethod.DELETE, "/account/user/{login}")
				     .access("#login == authentication.name or hasRole('ADMINISTRATOR')")
				.mvcMatchers(HttpMethod.POST, "/forum/post/{author}")
				     .access("#author == authentication.name") 
				.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}")
				     .access("#author == authentication.name")
				.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}")
				     .access("@customSecurity.checkPostAuthor(#id,authentication.name)")//@ через это обращыемся к классу
				.mvcMatchers(HttpMethod.DELETE, "/forum/post/{id}")
				     .access("@customSecurity.checkPostAuthor(#id,authentication.name) or hasRole('MODERATOR')")
				.anyRequest()
				    .authenticated()//сейчас все запросы требуют ауторизацыю 
		);

		return http.build();
	}
}
