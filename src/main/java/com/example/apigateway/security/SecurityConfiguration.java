package com.example.apigateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

  private static final String INSTRUCTOR = "INSTRUCTOR";
  private static final String GITLAB = "GITLAB";

  private final WebSecurityRoleProperties webSecurityRoleProperties;

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(
    ServerHttpSecurity http,
    ReactiveAuthenticationManager reactiveAuthenticationManager
  ) {
    return http
      .csrf()
      .disable()
      .authorizeExchange()
      .pathMatchers("/actuator/**")
      .permitAll()
      .pathMatchers("/config/monitor")
      .hasRole(GITLAB)
      .pathMatchers("/**")
      .hasRole(INSTRUCTOR)
      .anyExchange()
      .authenticated()
      .and()
      .authenticationManager(reactiveAuthenticationManager)
      .httpBasic()
      .and()
      .build();
  }

  @Bean
  public ReactiveAuthenticationManager reactiveAuthenticationManager(
    ReactiveUserDetailsService reactiveUserDetailsService
  ) {
    return new UserDetailsRepositoryReactiveAuthenticationManager(
      reactiveUserDetailsService
    );
  }

  @Bean
  public ReactiveUserDetailsService reactiveUserDetailsService() {
    PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    UserDetails instructor = User
      .builder()
      .username(webSecurityRoleProperties.getInstructor().getUsername())
      .password(webSecurityRoleProperties.getInstructor().getPassword())
      .passwordEncoder(encoder::encode)
      .roles(INSTRUCTOR)
      .build();
    UserDetails gitlab = User
      .builder()
      .username(webSecurityRoleProperties.getGitlab().getUsername())
      .password(webSecurityRoleProperties.getGitlab().getPassword())
      .passwordEncoder(encoder::encode)
      .roles(GITLAB)
      .build();
    return new MapReactiveUserDetailsService(instructor, gitlab);
  }
}
