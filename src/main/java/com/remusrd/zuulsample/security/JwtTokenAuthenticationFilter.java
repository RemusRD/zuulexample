package com.remusrd.zuulsample.security;

import com.remusrd.zuulsample.jwt.SecretKeyService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

	private final JwtConfig jwtConfig;

	private final SecretKeyService secretKeyService;

	public JwtTokenAuthenticationFilter(JwtConfig jwtConfig, SecretKeyService secretKeyService) {
		this.jwtConfig = jwtConfig;
		this.secretKeyService = secretKeyService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		final String authHeader = request.getHeader(jwtConfig.getHeader());
		if (authHeader == null || !authHeader.startsWith(jwtConfig.getPrefix())) {
			chain.doFilter(request, response);
			return;
		}
		final String token = authHeader.replace(jwtConfig.getPrefix(), "");
		try {
			final Claims claims = Jwts.parser()
					.setSigningKey(secretKeyService.getPublicKey())
					.parseClaimsJws(token)
					.getBody();
			final String username = claims.get("user_name").toString();
			if (username != null) {
				@SuppressWarnings("unchecked") final List<String> authorities = (List<String>)claims.get("authorities");
				final UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
						username, null,
						authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
		} catch (Exception e) {
			e.printStackTrace();
			SecurityContextHolder.clearContext();
		}
		chain.doFilter(request, response);
	}

}
