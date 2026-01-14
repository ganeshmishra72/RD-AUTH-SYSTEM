package com.rdmishra.auth.Services;

import org.springframework.web.multipart.MultipartFile;

import com.rdmishra.auth.DTO.UserDTO;

public interface UserService {

    // create user
    UserDTO cecreateUser(UserDTO userDTO);

    // get user by email id
    UserDTO getUserByEmailId(String email);

    // Update User
    UserDTO updateUser(UserDTO userDTO, String userId);

    // delete user
    void deleteUser(String userId);

    // get user by id;
    UserDTO getUserById(String userId);

    // get all users
    Iterable<UserDTO> getAllUser();

    UserDTO updaetProfileImage(MultipartFile file, String email);
}
