package vn.edu.iuh.fit.week10.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    /*public void globalConfig(AuthenticationManagerBuilder auth, PasswordEncoder encoder) throws Exception{
        auth.inMemoryAuthentication()
                .withUser(User.withUsername("admin")
                        .password(encoder.encode("admin"))
                        .roles("ADMIN")
                        .build())
                .withUser(User.withUsername("hao")
                        .password(encoder.encode("hao"))
                        .roles("HAO")
                        .build())
                .withUser(User.withUsername("dai")
                        .password(encoder.encode("dai"))
                        .roles("USER")
                        .build());
    }*/

    public void globalConfig(AuthenticationManagerBuilder auth, PasswordEncoder encoder, DataSource     dataSource) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .withDefaultSchema()
                .withUser(User.withUsername("admin")
                        .password(encoder.encode("admin"))
                        .roles("ADMIN"))
                .withUser(User.withUsername("hao")
                        .password(encoder.encode("hao"))
                        .roles("ADMIN","USER"));
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(auth->auth
                .requestMatchers("/","/home","/index").permitAll()
                .requestMatchers("/api/**").hasAnyRole("ADMIN","USER","HAO  ")
                .requestMatchers(("/admin/**")).hasRole("ADMIN")
                .anyRequest().authenticated()
        );
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
        http.httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
