package com.example.apigateway.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "api-gateway.security.role")
public class WebSecurityRoleProperties {

  private RoleCredentials instructor = new RoleCredentials();
  private RoleCredentials gitlab = new RoleCredentials();

  @Getter
  @Setter
  public static class RoleCredentials {

    private String username;
    private String password;
  }
}
