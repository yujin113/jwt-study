package study.jwt.jwttutorial.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity //기본적인 웹 보안을 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // h2-console 하위 모든 요청들과 파비콘 관련 요청은 Spring Security 로직을 수행하지 않도록
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**"
                        ,"/favicon.ico"
                ); // /h2-console/ 하위 모든 요청과 파비콘은 모두 무시하는 것으로 설정
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests() //httpServeltRequest를 사용하는 요청들에 대한 접근제한 설정하겠다는 의미
                .antMatchers("/api/hello").permitAll() //인증 없이 접근 허용하겠다
                .anyRequest().authenticated(); //나머지 요청은 모두 인증되어야 한다
    }
}
