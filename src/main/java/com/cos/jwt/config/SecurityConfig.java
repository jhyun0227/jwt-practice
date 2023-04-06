package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(new MyFilter3(), UsernamePasswordAuthenticationFilter.class)
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션을 사용하지 않겠다는 의미

                .and()
                //SPA와 사용시 포트가 다르기때문에 이 설정을 통해 CORS 허용 로직을 작성해야한다.
                .addFilter(corsFilter) //@CrossOrigin(인증이 없을떄), Security Filter에 등록(인증이 있을떄)

                .formLogin().disable() //form로그인이 아니기에 기능 비활성화(restful)
                .httpBasic().disable() //세션을 사용하지 않기 때문에 기본 httpBasic 방식을 사용하지 않고 토큰을 방식을 사용한다는 의미 (httpBasic은 보안상 문제 많음)

                .authorizeRequests()
                .antMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN")
                .antMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                .antMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll();

        return http.build();
    }
}
