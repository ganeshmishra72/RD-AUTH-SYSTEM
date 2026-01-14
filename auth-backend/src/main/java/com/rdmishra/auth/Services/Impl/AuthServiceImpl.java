package com.rdmishra.auth.Services.Impl;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.rdmishra.auth.DTO.UserDTO;
import com.rdmishra.auth.Services.AuthServices;
import com.rdmishra.auth.Services.UserService;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthServices {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDTO registerUser(UserDTO userDTO) {

        // all validator
        userDTO.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        return userService.cecreateUser(userDTO);
    }

}
