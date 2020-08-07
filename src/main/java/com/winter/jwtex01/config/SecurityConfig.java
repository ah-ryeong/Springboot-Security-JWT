package com.winter.jwtex01.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.winter.jwtex01.config.jwt.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// Csrf-Token 사용해제 -> 포트스맨 사용 X 
			http.csrf().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션을 유지하지 않겠다는 것
		.and()
			.formLogin().disable()
			.httpBasic().disable() // Http Jsession 막음
			.addFilter(new JwtAuthenticationFilter(authenticationManager())) // 내가 만든 인증필터
//			.addFilter(null)
			.authorizeRequests()
			.antMatchers("/api/v1/manager/**")
				.access("hasRole('Role_MANAGER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')") // 막을주소
			.antMatchers("/api/v1/admin/**")
				.access("hasRole('Role_ADMIN')") // 막을주소
			.anyRequest().permitAll();
//		http.cors().disable(); // 모든 도메인에서 자바스크립트로 요청이 가능하다. -> 내 사이트 매우 위험해지기 때문에 절대 걸면 안된다.
		// 이걸 허용하려면 부분적으로만 허용해야함
	}
}
