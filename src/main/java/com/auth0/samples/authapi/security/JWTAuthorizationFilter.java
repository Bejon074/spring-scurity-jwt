package com.auth0.samples.authapi.security;

import com.auth0.samples.authapi.user.ApplicationUser;
import com.auth0.samples.authapi.user.ApplicationUserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static com.auth0.samples.authapi.security.SecurityConstants.*;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private ApplicationUserRepository applicationUserRepository;

	public JWTAuthorizationFilter(AuthenticationManager authManager, ApplicationUserRepository applicationUserRepository) {
		super(authManager);
		this.applicationUserRepository = applicationUserRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req,
									HttpServletResponse res,
									FilterChain chain) throws IOException, ServletException {
		String header = req.getHeader(HEADER_STRING);
		if (header == null || !header.startsWith(TOKEN_PREFIX)) {
			chain.doFilter(req, res);
			return;
		}
		UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(req, res);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(HEADER_STRING);
		if (token != null) {
			// parse the token.
			String user = Jwts.parser()
					.setSigningKey(SECRET)
					.parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
					.getBody()
					.getSubject();
			System.out.println(">>>>>>>>>>>>>>>>>>>>"+user+"<<<<<<<<<<<<<<<<<<<<<<<<<<");

			ApplicationUser applicationUser = applicationUserRepository.findByUsername(user);
			List<GrantedAuthority> authorities = new ArrayList<>();
			if(applicationUser != null) {
				GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(applicationUser.getRole().name());
				authorities.add(grantedAuthority);
			}

			if (user != null) {
				return new UsernamePasswordAuthenticationToken(user, null, authorities);
			}
			return null;
		}
		return null;
	}
}
