package com.rdmishra.auth.Security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.cloudinary.Cloudinary;
import com.rdmishra.auth.DTO.ApiError;

import io.jsonwebtoken.lang.Arrays;

import tools.jackson.databind.ObjectMapper;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private JWTAuthenticationFilter jAuthenticationFilter;
    private AuthenticationSuccessHandler successHandler;

    public SecurityConfig(JWTAuthenticationFilter jAuthenticationFilter, AuthenticationSuccessHandler successHandler) {
        this.jAuthenticationFilter = jAuthenticationFilter;
        this.successHandler = successHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(c -> c.disable())
                .cors(Customizer.withDefaults())
                .sessionManagement(sa -> sa.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(
                        authorize -> authorize
                                .requestMatchers("/api/v1/auth/register").permitAll()
                                .requestMatchers("/api/v1/auth/login").permitAll()
                                .requestMatchers("/api/v1/auth/refresh").permitAll()
                                .requestMatchers("/api/v1/auth/logout").permitAll()
                                .requestMatchers("/error").permitAll()
                                .requestMatchers("/", "/login", "/login**", "/oauth2**").permitAll()
                                .anyRequest().authenticated())

                // oauth2 operation codes
                .oauth2Login(
                        oauth -> oauth.defaultSuccessUrl("https://auth-frontend-phi.vercel.app/dashboard/home", true)
                                .failureHandler((request, response, exception) -> {
                                    response.sendRedirect(
                                            "https://auth-frontend-phi.vercel.app/login?error=true");
                                }))
                .logout(AbstractHttpConfigurer::disable)
                .exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, e) -> {
                    // errormessage

                    e.printStackTrace();
                    response.setStatus(401);
                    response.setContentType("application/json");
                    String message = e.getMessage();
                    String error = (String) request.getAttribute("error");
                    if (error != null) {
                        message = error;
                    }

                    ApiError apierror = ApiError.of(HttpStatus.UNAUTHORIZED.value(), "Unauthorized Access!!", message,
                            request.getRequestURI());
                    ObjectMapper objectMapper = new ObjectMapper();
                    response.getWriter().write(objectMapper.writeValueAsString(apierror));

                })).addFilterBefore(jAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // This System in only use for inmemeory get information ---->
    // @Bean
    // public UserDetailsService userDetailsService() {
    // User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();
    // UserDetails user1 =
    // userBuilder.username("Ram").password("abc").roles("ADMIN").build();
    // UserDetails user2 =
    // userBuilder.username("Sneha").password("1lu").roles("ADMIN").build();

    // return new InMemoryUserDetailsManager(user1, user2);
    // }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.frontend-url}") String corsUrls) {

        String[] urls = corsUrls.trim().split(",");
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(urls));
        config.setAllowedMethods(List.of("GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "HEAD"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public Cloudinary cloudinary() {
        Map<String, String> config = new HashMap<>();
        config.put("cloud_name", "dy25vlvd5");
        config.put("api_key", "665939288427988");
        config.put("api_secret", "ENm9-aGt68fFj3jOZibeVsLCoao");
        return new Cloudinary(config);
    }
}
