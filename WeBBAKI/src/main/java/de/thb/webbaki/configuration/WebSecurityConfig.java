package de.thb.webbaki.configuration;

import de.thb.webbaki.security.CustomAuthenticationFailureHandler;
import de.thb.webbaki.security.MyUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final MyUserDetailsService userDetailsService;
    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authenticationProvider(authenticationProvider())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**", "/webjars/**", "/bootstrap/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                        .requestMatchers("/", "/home", "/register/**", "/success_register", "/confirmation/confirmByUser/**", "/datenschutz").permitAll()
                        .requestMatchers("/admin").hasAuthority("ROLE_SUPERADMIN")
                        .requestMatchers("/office").hasAuthority("ROLE_GESCHÄFTSSTELLE")
                        .requestMatchers("/threatmatrix/**").hasAuthority("ROLE_KRITIS_BETREIBER")
                        .requestMatchers("/report/company/**").hasAuthority("ROLE_KRITIS_BETREIBER")
                        .requestMatchers("/report/branche/**").hasAnyAuthority("ROLE_KRITIS_BETREIBER", "ROLE_BRANCHENADMIN", "ROLE_SEKTORENADMIN", "ROLE_BUNDESADMIN")
                        .requestMatchers("/report/sector/**").hasAnyAuthority("ROLE_KRITIS_BETREIBER", "ROLE_SEKTORENADMIN", "ROLE_BUNDESADMIN")
                        .requestMatchers("/report/national/**").hasAnyAuthority("ROLE_KRITIS_BETREIBER", "ROLE_BUNDESADMIN")
                        .requestMatchers("/snap/**", "/scenarios", "/adjustHelp").hasAuthority("ROLE_SUPERADMIN")
                        .requestMatchers("/help", "/horizontal_vertical_comparison/**").hasAuthority("ROLE_KRITIS_BETREIBER")
                        .requestMatchers("/confirmation/confirm/**").hasAuthority("ROLE_GESCHÄFTSSTELLE")
                        .anyRequest().permitAll()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .failureHandler(customAuthenticationFailureHandler)
                        .usernameParameter("username")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/").permitAll()
                )
                .sessionManagement(session -> session
                        .invalidSessionUrl("/login?expired")
                        .maximumSessions(1)
                        .expiredUrl("/logout")
                );

        http.headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives("form-action 'self'"))
        );

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }
}
