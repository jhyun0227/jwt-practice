package com.cos.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//스프링 시큐리티에서 UsernamePasswordAuthentication 가 있음
//login 요청에서 username, password 전송하면
//UsernamePasswordAuthenticationFilter가 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청읋 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도");

        // 1. username과 password를 받는다
        // 2. 정상인지 로그인시도를 해본다.
        // 3. authenticationManager로 로그인 시도 시 PrincipalDetailsService 호출
        // 4. loadByUsername 자동 실
        // 5. PrincipalDetails를 세션에 담고 (권한 관리를 위함)
        // 6. JWT 토큰을 만들어 응답하면된다.
        return super.attemptAuthentication(request, response);
    }
}
