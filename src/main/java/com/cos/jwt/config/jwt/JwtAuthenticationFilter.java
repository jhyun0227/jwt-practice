package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * 스프링 시큐리티에서 UsernamePasswordAuthentication 가 있음
 * /login 요청에서 username, password 전송하면
 * UsernamePasswordAuthenticationFilter가 동작
 * 하지만 우리가 Formlogin을 disable 했기 때문에 동작을 안한다.
 * 그렇기 때문에 이 필터를 다시 Security에 추가해야 한다.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // '/login' 요청읋 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter.attemptAuthentication - 로그인 시도");

        // 1. username과 password를 받는다
        // 2. 정상인지 로그인시도를 해본다.
        // 3. authenticationManager로 로그인 시도 시 PrincipalDetailsService 호출
        // 4. loadByUsername 자동 실행
        // 5. PrincipalDetails를 세션에 담고 (권한 관리를 위함)
        // 6. JWT 토큰을 만들어 응답하면된다.
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input = br.readLine()) != null) {
//                System.out.println("input = " + input);
//            }

            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //PrincipalDetailsService의 loadUserByUsername() 함수가 실행된다. (저 함수에서는 username만 받고 비밀번호는 따로 또 로직이있는데 거기까지 알필욘....)
            //토큰을 통해서 로그인시도를 해보고 정상적인 로그인이 되면 authentication 객체를 생성한다.
            //DB에 있는 username과 password가 일치한다.
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            //값이 있다는건 로그인이 정상적으로 되었다느 것
           PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("principal = " + principal.getUser());

            //authentication 객체가 session영역에 저장되어야 하는데 그 방법이 authentication을 return 하는 것이다.
            //굳이 리턴을 해 세션에 등록하는 이유는 권한 관리를 security가 대신 해줌으로서 편리하기 때문
            //JWT 토큰을 사용하면서 세션을 만들 이유는 없지만 단지 권한 처리 때문에 session에 등록
            return authentication;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    //위의 attemptAuthentication가 종료되고 인증이 정상적으로 되었으면 실행되는 함수
    //JWT 토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 응답 해준다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JwtAuthenticationFilter.successfulAuthentication - 실행");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUsername())
                .sign(Algorithm.HMAC512("cos"));

        System.out.println("jwtToken = " + jwtToken);

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
