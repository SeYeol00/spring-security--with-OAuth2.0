package com.cos.securityex01.model;

import java.sql.Timestamp;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import org.hibernate.annotations.CreationTimestamp;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// ORM - Object Relation Mapping

@Builder
@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
public class User {
	@Id // primary key
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;
	private String username; // 구글 때문에 중복 될 일이 없다.
	private String password; // 암호화 해서 넣으면 된다.
	private String email; // gmail.com
	private String role; //ROLE_USER, ROLE_ADMIN
	// OAuth를 위해 구성한 추가 필드 2개
	private String provider; // "google", attribute 정보로 강제해서 넣는다.
	private String providerId; // 10290190192
	@CreationTimestamp
	private Timestamp createDate;
}
