package com.cos.securityex01.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.securityex01.model.User;
import com.cos.securityex01.repository.UserRepository;


// 시큐리티 설정에 loginProcessingUrl("/login");
// /login 요청이 오면 자동으로 UserDetailsService IoC 되어 있는 loadUserByUsername 함수가 실행이 된다.
@Service
public class PrincipalDetailsService implements UserDetailsService{

	@Autowired
	private UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username);
		if(user == null) {
			return null;
		}else {// 스프링 시큐리티가 유저에 관한 세션을 만든다. 시큐리티 세션 -> 인증을 해준다.
			// 시큐리티 세션(내부 Authentication(내부 UserDetails))
			return new PrincipalDetails(user);
		}
		
	}

}
