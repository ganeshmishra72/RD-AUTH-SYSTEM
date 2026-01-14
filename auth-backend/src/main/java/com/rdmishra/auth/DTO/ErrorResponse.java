package com.rdmishra.auth.DTO;

import org.springframework.http.HttpStatus;

public record ErrorResponse(
        String message,
        HttpStatus status) {
}
