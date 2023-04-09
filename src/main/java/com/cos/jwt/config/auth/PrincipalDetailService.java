package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import com.cos.jwt.respository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * http://localhost:8080/login => Security의 기본적인 로그인 요청 주소 (Form을 사용할 경우)
 * 하지만 이제 Form로그인을 사용하지 않기때문에 저 주소로는 이 서비스가 동작을 안한다.
 * 그래서 직접 이 서비스를 동작시키는 필터를 만들어야 한다.
 * 그것이 UsernamePasswordAuthenticationFilter을 구현한 필터 (프로젝트에서 JwtAuthenticationFilter)
 */
@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrinicpalDetailService.loadUserByUsername - 실행");
        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
}
