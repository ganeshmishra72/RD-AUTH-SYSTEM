package com.rdmishra.auth.Security;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import com.rdmishra.auth.Helper.UserHelper;
import com.rdmishra.auth.Repository.UserRepo;
import com.rdmishra.auth.Services.JWTService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final UserRepo userRepo;
    private Logger logger = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        logger.info("Authorization : {}", header);

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            if (!jwtService.isAccessToken(token)) {
                filterChain.doFilter(request, response);
                return;
            }
            try {
                Jws<Claims> pares = jwtService.parse(token);
                Claims payload = pares.getPayload();
                String usedId = payload.getSubject();
                UUID userUuid = UserHelper.parseUUID(usedId);

                userRepo.findById(userUuid).ifPresent(
                        user -> {

                            if (user.isEnable()) {

                                List<GrantedAuthority> authorities = user.getRoles() == null ? List.of()
                                        : user.getRoles().stream()
                                                .map(role -> new SimpleGrantedAuthority(role.getName()))
                                                .collect(Collectors.toList());

                                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                        user,
                                        null,
                                        authorities);

                                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                                // final line is set
                                if (SecurityContextHolder.getContext().getAuthentication() == null)
                                    SecurityContextHolder.getContext().setAuthentication(authentication);
                            }

                        });

            } catch (ExpiredJwtException e) {
                request.setAttribute("error", "Token Experied");

            } catch (Exception e) {
                request.setAttribute("error", "Invalid Experied");

            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getRequestURI().startsWith("/api/v1/auth");

    }

}
