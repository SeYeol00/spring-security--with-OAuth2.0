package com.cos.securityex01.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.securityex01.config.oauth.PrincipalOauth2UserService;

@Configuration // IoC 빈(bean)을 등록
@EnableWebSecurity // 필터 체인 관리 시작 어노테이션, 스프링 시큐리티 필터가 필터 체인에 등록된다.
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
// 특정 주소 접근시 권한 및 인증을 위한 어노테이션 활성화, secured 어노테이션 활성화, preAuthorize, prePost 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;

	// 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}// 스프링 시큐리티를 사용하려면 비밀번호를 인코딩(암호화)해야한다. 리턴값은 String이다.

	//Spring Security 5.3.3에서 공식 지원하는 PasswordEncoder 구현 클래스들은 아래와 같습니다.
	//BcryptPasswordEncoder : BCrypt 해시 함수를 사용해 비밀번호를 암호화
	//Argon2PasswordEncoder : Argon2 해시 함수를 사용해 비밀번호를 암호화
	//Pbkdf2PasswordEncoder : PBKDF2 해시 함수를 사용해 비밀번호를 암호화
	//SCryptPasswordEncoder : SCrypt 해시 함수를 사용해 비밀번호를 암호화
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.csrf().disable(); // 세션 사용 안 한다.
		http.authorizeRequests()
			.antMatchers("/user/**").authenticated()// "/user/**"이라는 url은 인증이 필요해, 인증만 되면 들어갈 수 있는 주소

				// 						인증뿐만 아니라 권한이 필요해
			//.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
			//.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN') and hasRole('ROLE_USER')")
			.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll()
		.and()
			.formLogin()
			.loginPage("/login") //login이 안 되어 있다면 다 리다이렉트를 걸어준다.
//				.usernameParameter("username") username의 파라미터를 바꾸고 싶으면 이걸 쓴다.
			.loginProcessingUrl("/loginProc") // /loginProc 주소가 호출이 되면 시큐리티가 낚아채 대신 로그인을 진행해줍니다.
			.defaultSuccessUrl("/") // 로그인이 완료되면 리다이렉트되는 주소
		.and()
			.oauth2Login()
			.loginPage("/login") // 로그인 페이지 url을 넣어야 리다이렉트된다.

				// 구글로그인이 완료된 뒤의 후처리
				// 1. 코드 받기(인증)
				// 2. 엑세스 토큰(권한,인가)
				// 3. 사용자 프로필 정보를 가져오고
				// 4. 그 정보를 토대로 회원가입을 자동으로 진행시킴
				// 4 - 2. 부족한 정보면
				// Tip. 코드X, (엑세스 토큰 + 사용자 프로필 정보 O)
			.userInfoEndpoint()
				// 타입이 OAUth2 유저 서비스가 되어야한다. 인터페이스가 따로 있다.
			.userService(principalOauth2UserService);
	}
}





