package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import com.cos.jwt.respository.UserRepository;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfig corsConfig;
    private final UserRepository userRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
//                .addFilterBefore(new MyFilter3(), UsernamePasswordAuthenticationFilter.class)
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션을 사용하지 않겠다는 의미

                .and()
                .formLogin().disable() //form로그인이 아니기에 기능 비활성화(restful)
                .httpBasic().disable() //세션을 사용하지 않기 때문에 기본 httpBasic 방식을 사용하지 않고 토큰을 방식을 사용한다는 의미 (httpBasic은 보안상 문제 많음)

                .apply(new MyCustomDsl()) //커스텀 필터 등록

                .and()
                .authorizeRequests()
                .antMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN")
                .antMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                .antMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll();

        return http.build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    //SPA와 사용시 포트가 다르기때문에 이 설정을 통해 CORS 허용 로직을 작성해야한다.
                    .addFilter(corsConfig.corsFilter()) //@CrossOrigin(인증이 없을떄), Security Filter에 등록(인증이 있을떄)

                    //'/login' 호출할경우 발생되는 필터
                    //DB정보를 조회해서 올바른 사용자인지 조회 후 토큰 발급
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))

                    //위 authorizeRequests()에 등록된 경로에 접근하려했을때 실행된다.
                    //요청을 통해 전해지는 JWT토큰을 이용한다.`
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }
    }
}
