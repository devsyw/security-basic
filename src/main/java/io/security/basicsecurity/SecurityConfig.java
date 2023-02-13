package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

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
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        // login
        http
                .formLogin()
//                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("id")
                .passwordParameter("pw")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication : " + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception : " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
                .permitAll()
                ;

        // logout
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
                .deleteCookies("remember-me"); // 삭제할 쿠키명
        
        // remember on this computer
        http
                .rememberMe()
//                .rememberMeParameter("remember-me") // 기본 파라미터명은 remember-me
//                .tokenValiditySeconds(3600) //토큰 만료까지의 시간 default는 14일
//                .alwaysRemember(true) //rememberMe 기능이 활성화되지 않아도 항상 실행, 일반적으로 false
                .userDetailsService(userDetailsService);
        
        // 동시 세션 제어
        http
                .sessionManagement()
                .maximumSessions(1) //최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(true) // 동시 로그인 차단함, false : 기존 세션 만료(default)
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

        // Con
    }
}