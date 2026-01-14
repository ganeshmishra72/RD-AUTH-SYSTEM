package com.rdmishra.auth.DTO;

public record TokenRespnose(
        String accessToken,
        String refreshToken,
        long experin,
        String tokenType,
        UserDTO user

) {
    public static TokenRespnose of(String accessToken, String refreshToken, long experin, UserDTO user) {
        return new TokenRespnose(accessToken, refreshToken, experin, "Bearer", user);
    }

}
