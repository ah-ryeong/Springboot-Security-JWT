package com.winter.jwtex01.config.jwt;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.winter.jwtex01.config.auth.PrincipalDetails;
import com.winter.jwtex01.dto.LoginRequestDto;
import com.winter.jwtex01.model.User;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	
	// Authentication 객체 만들어서 리턴 (원래 Authentication은 원래는 자동으로 만들어지지만 내가 커스터마이징할거기 때문에 오버라이딩해줌)
	// => 의존 : AuthenticationManager
	// attemptAuthentication : 인증 요청시 실행되는 함수 -> /login일때만 실행됨 (기본적인 인증요청주소가 login이라서)
	@Override  
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		// username, password 뽑아내기, request에 있는 username, password 파싱해서 자바 Object로 받기
		ObjectMapper om = new ObjectMapper();
		LoginRequestDto loginRequestDto = null;
		
		// 파싱하다가 리셉션이 발생할 수 있기 때문에 try-catch 해준다.
		try {
			loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class); //request.getInputStream() : request에 있는 모든 정보가 들어옴 / Object Mapper 정리해보기
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// username, password Token 생성
		UsernamePasswordAuthenticationToken authenticationToken =
				new UsernamePasswordAuthenticationToken(
						loginRequestDto.getUsername(), // 인증주체, 접근주체 자리, id, password
						loginRequestDto.getPassword());
		
		// Authenticate() 함수가 호출되면 인증 프로바이더가 
		// UserDetailService의 loadUerByUsername(토큰의 첫 번째 파라메터)을 호출하고
		// UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential -> request 받은 값(사용자로부터 받은 값))과 
		// UserDetails(DB값)의 getPassword() 함수로 비교해서 동일하면
		// Authentication 객체를 만들어서 필터체인으로 리턴해준다.
		// Tip : 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
		// Tip : 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder임
		// 결론 : 인증 프로바이더에게 알려줄 필요가 없다.
		Authentication authentication = 
				authenticationManager.authenticate(authenticationToken);
		
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("Authentication : " + principalDetails.getUser().getUsername());
		
		return authentication;
	}

	// JWT Token 생성해서 response에 담아주기
	@Override // Authentication이 만들어지면 동작한다.
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		// ﻿JWT Token 만들기
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+864000000)) // 만료시간
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("MilkTea".getBytes()));
		
		response.addHeader("Authorization", "Bearer "+ jwtToken);
//		super.successfulAuthentication(request, response, chain, authResult);
	}
	
}
