package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import com.cos.jwt.respository.UserRepository;

/**
 * Security가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 가 있다.
 * 권한이나 인증이 필요한 특정 주소를 요청했을 때, 위 필터를 무조건 타게 되어있다.
 * 만약 권한이나 인증이 필요한 주소가 아니라면 이 필터는 동작하지 않는다.
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    //인증이나 권한이 필요한 주소 요청이 있을 떄 해당 필터를 타게 될것
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        System.out.println("JwtAuthorizationFilter.doFilterInternal - 인증이나 권환이 필요한 주소 요청이 됨");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader = " + jwtHeader);

        //header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        //JWT 토큰을 검증해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        System.out.println("jwtToken = " + jwtToken);

        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();

        //서명이 정상적으로 됨
        if (username != null) {
            User user = userRepository.findByUsername(username);

            //JWT토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            PrincipalDetails principalDetails = new PrincipalDetails(user);
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }

    }
}
