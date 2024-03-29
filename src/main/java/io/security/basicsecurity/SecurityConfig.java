package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    // 인메모리로 가상의 유저를 만듦(테스트용)
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * 권한설정과 표현식
         * - 선언적 방식
         * - 동적방식 DB 연동 프로그래밍
         */

        //선언적 방식
        /**
         *  > authenticated() : 인증된 사용자의 접근을 허용
         *  > fullyAuthenticated() : 인증된 사용자의 접근을 허용, rememberMe 인증 제외
         *  > permitAll() : 무조건 접근을 허용
         *  > denyAll() : 무조건 접근을 허용하지 않음
         *  > anonymous() : 익명사용자의 접근을 허용
         *  > rememberMe() : 기억하기를 통해 인증된 사용자의 접근을 허용
         *  > access("hasRole('ADMIN')") : 주어진 SpEL표현식의 평가 결과가 true 이면 접근을 허용
         *  > hasRole(String) : 사용자가 주어진 역할이 있다면 접근을 허용
         *  > hasAuthority(String) : 사용자가 주어진 권한이 있다면
         *  > hasAnyRole(String...) : 사용자가 주어진 권한이 있다면 접근을 허용
         *  > hasAnyAuthority(String...) : 사용자가 주어진 권한 중 어떤 것이라도 있다면 접근을 허용
         *  > hasIpAddress(String) : 주어진 IP로부터 요청이 왔다면 접근을 허용
         */
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('SYS') or hasRole('ADMIN')") // 윗줄과 순서바뀌면 곤란
                .anyRequest().authenticated();

        http
                .csrf().disable(); // 기본적으로 활성화되어있음 (disable() 부분 삭제 상태), csrfFilter 디버깅하면 헤더에 토큰받아서 테스트가능

        // 로그인 후 원래 요청페이지로 리다이렉트
        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        // 인증 성공 후 사용자의 캐시를 꺼내와 원래 가고자 했던 페이지로 이동시켜줌
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                });

        // 인증 및 인가 예외처리
        http
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                }) // 인증 실패시 처리
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                }); // 인가 실패시 처리

        // login
        http
                .formLogin()
                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("id")
                .passwordParameter("pw")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll()
                ;

        // logout
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me"); // 삭제할 쿠키명
        
        // remember on this computer
        http
                .rememberMe()
                .rememberMeParameter("remember-me") // 기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600) //토큰 만료까지의 시간 default는 14일
                .alwaysRemember(true) //rememberMe 기능이 활성화되지 않아도 항상 실행, 일반적으로 false
                .userDetailsService(userDetailsService);
        
        // 동시 세션 제어(세션 차단/고정 보호)
        http
                .sessionManagement()
                .maximumSessions(1) //최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(true); // 동시 로그인 차단함, false : 기존 세션 만료(default)
        // 동시 세션 제어(세션 갱신 - 범용적)
        http
                .sessionManagement()
                .maximumSessions(1) //최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(false) // 동시 로그인 차단함, false : 기존 세션 만료(default)
                .expiredUrl("/expired"); // 세션이 만료된 경우 이동 할 페이지

        // 세션 고정 보호
        http
                .sessionManagement()
                .sessionFixation().changeSessionId(); // 기본값 (none, migrateSession, newSession)

        // 세션 정책
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // 기본값
        /**
         * SessionCreationPolicy.Always : 스프링 시큐리티가 항상 세션 생성
         * SessionCreationPolicy.IF_REQUIRED : 스프링 시큐리티가 필요 시 생성(기본값)
         * SessionCreationPolicy.Never : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
         * SessionCreationPolicy.Stateless : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음(JWT만 인증할때 사용)
         */

    }
}