package com.oliveira.willy.securityProject.jwt;

import com.google.common.net.HttpHeaders;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "application.jwt")
@NoArgsConstructor
@Getter
@Setter
public class JwtConfig {
    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpiratinAfterDays;

    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }
}
