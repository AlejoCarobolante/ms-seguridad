package security.demo_jwt.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import security.demo_jwt.Domain.User;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String SECRET_KEY;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    // --- 1. Generar Access Token (Usa el tiempo corto) ---
    public String getToken(UserDetails user) {
        return buildToken(new HashMap<>(), user, jwtExpiration);
    }

    // --- 2. Generar Refresh Token (Usa el tiempo largo) ---
    public String getRefreshToken(UserDetails user) {
        return buildToken(new HashMap<>(), user, refreshExpiration);
    }

    // --- 3. Método Constructor Privado (Recibe la expiración) ---
    private String buildToken(Map<String, Object> extractClaims, UserDetails user, long expiration) {
        return Jwts.builder()
                .setClaims(extractClaims)
                .setSubject(((User) user).getEmail()) // Mantenemos tu lógica de usar Email
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // <--- AQUI SE USA LA VARIABLE
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String getEmailFromToken(String token) {
        return getClaim(token, Claims::getSubject);
    }

    // Tu validación corregida (Email vs Email)
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String email = getEmailFromToken(token);
        String userEmail = ((User) userDetails).getEmail();
        return (email.equals(userEmail)) && !isTokenExpired(token);
    }

    private Claims getAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T getClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = getAllClaims(token);
        return  claimsResolver.apply(claims);
    }

    private Date getExpiration(String token){
        return getClaim(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token){
        return getExpiration(token).before(new Date());
    }
}