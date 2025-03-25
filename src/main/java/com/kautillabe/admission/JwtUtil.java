package com.kautillabe.admission;

import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtil {

	private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

	private final String SECRET_KEY = "BjFWgJ0ZqK7gUDvh2bAE8R8ZJqjmYBAj8ug3ZDYlQag=";
																						
	private final long EXPIRATION_TIME = 2 * 60 * 1000; // 2 minutes

	 public String getJwtFromHeader(HttpServletRequest request) {
	        String bearerToken = request.getHeader("Authorization");
	        logger.debug("Authorization Header: {}", bearerToken);
	        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
	            return bearerToken.substring(7); // Remove Bearer prefix
	        }
	        return null;
	    }

	    public String generateTokenFromUsername(UserDetailsImpl userDetails) {
	    	System.out.println("==============");
	        String username = userDetails.getUsername();
	        String roles = userDetails.getAuthorities().stream()
	                .map(authority -> authority.getAuthority())
	                .collect(Collectors.joining(","));
	        return Jwts.builder()
	        		.setSubject(username)
	                .claim("roles", roles)
	                .setIssuedAt(new Date())
	                .setExpiration(new Date((new Date()).getTime() + EXPIRATION_TIME))
	                .signWith(key())
	                .compact();
	    }

	    public String getUserNameFromJwtToken(String token) {
	        return Jwts.parserBuilder().setSigningKey(key()).build()
	                   .parseClaimsJws(token).getBody().getSubject();
	      }


	    private Key key() {
	        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
	    }

	    public boolean validateJwtToken(String authToken) {
	        try {
	            System.out.println("Validate");
	            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);

	            return true;
	        } catch (MalformedJwtException e) {
	            logger.error("Invalid JWT token: {}", e.getMessage());
	        } catch (ExpiredJwtException e) {
	            logger.error("JWT token is expired: {}", e.getMessage());
	        } catch (UnsupportedJwtException e) {
	            logger.error("JWT token is unsupported: {}", e.getMessage());
	        } catch (IllegalArgumentException e) {
	            logger.error("JWT claims string is empty: {}", e.getMessage());
	        }
	        return false;
	    }
}
