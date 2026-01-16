package com.rdmishra.auth.Security;

import org.springframework.http.HttpHeaders;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseCookie.ResponseCookieBuilder;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;

@Service
@Getter
public class CookieServices {

    private final String refreshTokenCookenName;
    private final boolean cookiesecure;
    private final boolean cookiehttponly;
    private final String cookiesamepath;
    private final String cookieDomain;

    public CookieServices(
            @Value("${security.jwt.refresh-token-cookie-name}") String refreshTokenCookenName,
            @Value("${security.jwt.cookie-secure}") boolean cookiesecure,
            @Value("${security.jwt.cookie-http-only}") boolean cookiehttponly,
            @Value("${security.jwt.cookie-same-site}") String cookiesamepath,
            @Value("${security.jwt.cookie-domain-name:}") String cookieDomain) {
        this.refreshTokenCookenName = refreshTokenCookenName;
        this.cookiesecure = cookiesecure;
        this.cookiehttponly = cookiehttponly;
        this.cookiesamepath = cookiesamepath;
        this.cookieDomain = cookieDomain;
    }

    public void attatchRefreshCookie(HttpServletResponse response, String value, int maxage) {
        ResponseCookieBuilder resfreshtokenbulider = ResponseCookie.from(refreshTokenCookenName, value)
                .httpOnly(cookiehttponly)
                .maxAge(maxage)
                .secure(cookiesecure)
                .path("/")
                .sameSite(cookiesamepath);
        if (cookieDomain != null && !cookieDomain.isBlank()) {
            resfreshtokenbulider.domain(cookieDomain);
        }

        ResponseCookie responseCookie = resfreshtokenbulider.build();
        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
    }

    public void cleareRefreshCookie(HttpServletResponse response) {
        ResponseCookieBuilder bulider = ResponseCookie.from(refreshTokenCookenName, "")
                .httpOnly(cookiehttponly)
                .maxAge(0)
                .secure(cookiesecure)
                .path("/")
                .sameSite(cookiesamepath);
        if (cookieDomain != null && !cookieDomain.isBlank()) {
            bulider.domain(cookieDomain);
        }

        ResponseCookie responseCookie = bulider.build();
        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
    }

    public void addNoStoreHeader(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Pragma", "no-cache");
    }

}
