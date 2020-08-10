package com.winter.jwtex01.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.winter.jwtex01.config.auth.PrincipalDetails;
import com.winter.jwtex01.config.auth.SessionUser;
import com.winter.jwtex01.model.User;
import com.winter.jwtex01.repository.UserRepository;

// 인가(해당 값이 유효할때 들어오게 하는거)
public class JwtAuthorizaionFilter extends BasicAuthenticationFilter {
	// 헤더를 검증해서 SecurityContextHoler에 넣어준다.

	private UserRepository userRepository;

	public JwtAuthorizaionFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository; 
	}

	// 서명하기
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// 헤더값 확인
		String header = request.getHeader(JwtProperties.HEADER_STRING); // null 이 아니어야함
		if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) { // null 값이랑 Bearer가 있는지 확인
			chain.doFilter(request, response);
			return;
		}
		System.out.println("header : " + header);

		// 서명하기(값이 잘 들어온 경우)
		String token = request.getHeader(JwtProperties.HEADER_STRING) // 위에서 검증했기 때문에 무조건 있음
				// (중요) Jwt Token 만들 때는 2가지를 처리해야함
				// 1. 공백이 있으면 안됨 2. 웹으로 데이터가 들어오기 때문에 =, ==이라는 패딩이 들어올 수 있음 -> 이런게 들어오면 안됨

				// 공백, == 날리기
				.replace(JwtProperties.TOKEN_PREFIX, "")
				.replace(" ", "")
				.replace("=", "");

		// 토큰 검증 : a, b의 값을 secret 값으로 해쉬 -> 해당 값이 C를 base64로 디코딩 한 값과 같아야함
		// 이게 인증이기 때문에 AuthenticationManager 필요없음
		// 내가 SecurityContext에 직접접근해서 세션을 만들 때 자동으로 UserDetailsService에 있는
		String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
				.build()
				.verify(token) // 서명
				.getClaim("username").asString();

		
		if (username != null) {
			System.out.println("username : "+username);
			System.out.println("1");
			
			System.out.println("2");

			User user = userRepository.findByUsername(username);
			
			// 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해 
			// 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
			PrincipalDetails principalDetails = new PrincipalDetails(user);
			Authentication authentication =
					new UsernamePasswordAuthenticationToken(
							principalDetails, //나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
							null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
							principalDetails.getAuthorities());
			
			// 강제로 시큐리티의 세션에 접근하여 값 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			// 인증은 토큰 검증시 끝, 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한처리를 위해서
			// 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장해준다.
			SessionUser sessionUser = SessionUser.builder()
					.id(user.getId())
					.username(user.getUsername())
					.roles(user.getRoleList())
					.build();
			System.out.println("sessionUser 검증 : " + sessionUser);
			
			HttpSession session = request.getSession();
			session.setAttribute("sessionUser", sessionUser);
		}
		
		chain.doFilter(request, response); 
	}
}
