package org.limir.springjwtsecurity;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.*;

import java.util.Date;

@Component
public class JwtCore {
    @Value("${application.security.jwt.key}")
    private String secret;
    @Value("${application.security.jwt.expiration}")
    private int lifetime;

    @Deprecated
    public String generateToken(Authentication authentication) {
        UserDetailsImpl userDetailsImpl = (UserDetailsImpl)authentication.getPrincipal();
        return Jwts.builder().setSubject((userDetailsImpl.getUsername())).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + lifetime))
                .signWith(SignatureAlgorithm.HS256,secret)
                .compact();
    }

    @Deprecated
    public String getNameFromJwt(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getSubject();
    }
}
