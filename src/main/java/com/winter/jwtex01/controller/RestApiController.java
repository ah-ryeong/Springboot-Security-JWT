package com.winter.jwtex01.controller;

import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.winter.jwtex01.config.auth.SessionUser;
import com.winter.jwtex01.model.User;
import com.winter.jwtex01.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor // final 붙은거 생성자 만들어줌
@RequestMapping("api/v1") // controller 진입 주소
//@CrossOrigin // CORS 허용 
public class RestApiController {
	
	// @Autowired : 스프링 전용 어노테이션(기본원리-> 생성자) = @inject : 스프링 뿐만 아니라 다른 코드에도 적용가능)
	// final 의 특징 : 무조건 초기화가 돼야한다. -> 초기화하기 위해서 생성자를 무조건 만들어줘야함(강제성)
	private final UserRepository UserRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	// 모든 사람이 접근가능
	@GetMapping("home")
	public String home() {
		return "<h1>home</h1>";
	}
	
	// Tip : JWT를 사용하면 UserDetailsService를 호출하지 않기 때문에 @AuthenticationPrincipal 사용 불가능.
	// 왜냐하면 @AuthenticationPrincipal은 UserDetailsService에서 리턴될 때 만들어지기 때문이다.
	
	// 매니저, admin 접근가능
	@GetMapping("manager/reports")
	public String reports() {
		return "<h1>reports</h1>";
	}
	
	// admin만 접근가능
	@GetMapping("admin/users")
	public List<User> users() {
		return null;
	}
	
	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		UserRepository.save(user);
		return "회원가입완료";
	}
	
	@GetMapping("user")
	public String user(HttpSession session) {
		SessionUser sessionUser = (SessionUser) session.getAttribute("sessionUser");
		System.out.println("principal : " + sessionUser.getId());
		System.out.println("principal : " + sessionUser.getUsername());
		System.out.println("principal : " + sessionUser.getRoles());
		
		return "<h1>user</h1>";
	}
}
