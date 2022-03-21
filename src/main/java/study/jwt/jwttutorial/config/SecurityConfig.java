package study.jwt.jwttutorial.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import study.jwt.jwttutorial.jwt.JwtAccessDeniedHandler;
import study.jwt.jwttutorial.jwt.JwtAuthenticationEntryPoint;
import study.jwt.jwttutorial.jwt.JwtSecurityConfig;
import study.jwt.jwttutorial.jwt.TokenProvider;

@EnableWebSecurity //기본적인 웹 보안을 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true) //@PreAuthorize 어노테이션을 메소드 단위로 추가하기 위해 적용
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // h2-console 하위 모든 요청들과 파비콘 관련 요청은 Spring Security 로직을 수행하지 않도록
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**"
                        , "/favicon.ico"
                ); // /h2-console/ 하위 모든 요청과 파비콘은 모두 무시하는 것으로 설정
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //우리는 토큰을 사용하는 방식이기 때문에 csrf를 disable
                .csrf().disable()

                //Exception 핸들링할 때 우리가 만들었던 클래스로 추가
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // enable h2-console
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 세션을 사용하지 않기 때문에 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests() //httpServeltRequest를 사용하는 요청들에 대한 접근제한 설정하겠다는 의미
                .antMatchers("/api/hello").permitAll() //인증 없이 접근 허용하겠다
                .antMatchers("/api/authenticate").permitAll() //로그인 API
                .antMatchers("/api/signup").permitAll() //회원가입 API
                .anyRequest().authenticated() //나머지 요청은 모두 인증되어야 한다

                .and()
                .apply(new JwtSecurityConfig(tokenProvider)); //JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig 클래스도 적용해주기
    }
}
