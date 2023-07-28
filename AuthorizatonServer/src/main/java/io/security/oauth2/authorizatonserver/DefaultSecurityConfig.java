
package io.security.oauth2.authorizatonserver;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class DefaultSecurityConfig {

	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {


		// 카카오 로그인시 페이지 띄어주는 부분과 같다.
		http.authorizeRequests(request -> request.anyRequest().authenticated());
		http.formLogin();
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(userDetailsService());
		http.authenticationProvider(daoAuthenticationProvider);

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService(){
		UserDetails user = User.withUsername("user").password("{noop}1234").authorities("ROLE_USER").build();
		return new InMemoryUserDetailsManager(user);
	}
}