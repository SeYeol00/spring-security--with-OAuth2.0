package com.cos.securityex01.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.cos.securityex01.model.User;

import lombok.Data;

// Authentication 객체에 저장할 수 있는 유일한 타입
// 로그인 진행이 완료되면 시큐리티 세션을 만들어준다. Security ContextHolder
// 오브젝트 타입 => Authentication 타입 객체
// Authentication 안에 User 정보가 있어야 됨
// User 오브젝트타입 => UserDetails 타입 객체
// Security Session => Authentication => UserDetails
// 두 가지를 상속받아 사용한다.
public class PrincipalDetails implements UserDetails, OAuth2User{

	private static final long serialVersionUID = 1L;
	private User user; // 콤포지션
	private Map<String, Object> attributes;

	// 일반 시큐리티 로그인시 사용
	public PrincipalDetails(User user) {
		this.user = user;
	}
	
	// OAuth2.0 로그인시 사용
	public PrincipalDetails(User user, Map<String, Object> attributes) {
		this.user = user;
		this.attributes = attributes;
	}
	
	public User getUser() {
		return user;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	// 비밀번호의 기간이 지났니? 오래 사용한 거 아니니?
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	// 휴면계정과 같아진다면 false
	@Override
	public boolean isEnabled() {
		return true;
	}


	// 해당 유저의 권한 즉, 인가를 리턴하는 곳
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collet = new ArrayList<GrantedAuthority>();
		collet.add(()->{ return user.getRole();});
		return collet;
	}

	// 리소스 서버로 부터 받는 회원정보
	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	// User의 PrimaryKey, 거의 쓰지도 않는다.
	@Override
	public String getName() {
		return user.getId()+"";
	}
	
}
