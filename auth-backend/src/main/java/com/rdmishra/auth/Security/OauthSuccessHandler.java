package com.rdmishra.auth.Security;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import com.rdmishra.auth.Entity.Provider;
import com.rdmishra.auth.Entity.RefreshToken;
import com.rdmishra.auth.Entity.User;
import com.rdmishra.auth.Repository.RefreshTokenRepo;
import com.rdmishra.auth.Repository.UserRepo;
import com.rdmishra.auth.Services.JWTService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OauthSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepo repo;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final JWTService jwtService;
    private final CookieServices cookieServices;
    private final RefreshTokenRepo refreshTokenRepo;

    @Value("${app.auth.frontend.success-url}")
    private String frontendSucces;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        logger.info("Successfully Authentication");
        logger.info(authentication.toString());

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String registrationId = "unknown";

        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        logger.info("registraionId" + registrationId);
        logger.info("user:" + oAuth2User.getAttributes().toString());

        User user;

        switch (registrationId) {
            case "google" -> {
                String googleId = oAuth2User.getAttributes().getOrDefault("sub", "").toString();
                String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
                String name = oAuth2User.getAttributes().getOrDefault("name", "").toString();
                String picture = oAuth2User.getAttributes().getOrDefault("picture", "").toString();
                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .imageUrl(picture)
                        .enable(true)
                        .provider(Provider.GITHUB)
                        .providerId(googleId)
                        .build();
                user = repo.findByEmail(email).orElseGet(() -> repo.save(newUser));
            }
            case "github" -> {
                String name = oAuth2User.getAttributes().getOrDefault("login", "").toString();
                String githubId = oAuth2User.getAttributes().getOrDefault("id", "").toString();
                String image = oAuth2User.getAttributes().getOrDefault("avatar_url", "").toString();
                String email = (String) oAuth2User.getAttributes().get("email");
                if (email == null) {
                    email = name + "@github.com";
                }
                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .imageUrl(image)
                        .enable(true)
                        .provider(Provider.GOOGLE)
                        .providerId(githubId)
                        .build();
                user = repo.findByEmail(email).orElseGet(() -> repo.save(newUser));
            }
            default -> {
                throw new RuntimeException("Invalid Registration Id");
            }

        }

        // refresh token
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expireAt(Instant.now().plusSeconds(jwtService.getRefreshTtlseconds()))
                .revoked(false)
                .build();

        refreshTokenRepo.save(refreshToken);

        String accessToken = jwtService.generateAccessToken(user);
        String refresTokenOb = jwtService.generateRefreshToken(user, refreshToken.getJti());

        cookieServices.attatchRefreshCookie(response, refresTokenOb, (int) jwtService.getRefreshTtlseconds());

        // response.getWriter().write("Login Succesffuly");
        response.sendRedirect(frontendSucces);

    }

}
