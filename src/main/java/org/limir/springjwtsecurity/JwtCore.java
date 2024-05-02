package org.limir.springjwtsecurity;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtCore {
    @Value("${application.security.jwt.key}")
    private String secret;
    @Value("${application.security.jwt.expiration}")
    private int lifetime;
}
