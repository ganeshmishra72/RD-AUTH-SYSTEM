package com.rdmishra.auth.DTO;

public record LoginRequest(
        String email,
        String password) {

}
