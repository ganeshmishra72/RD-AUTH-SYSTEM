package com.rdmishra.auth.Services.Impl;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.cloudinary.Cloudinary;
import com.rdmishra.auth.DTO.UserDTO;
import com.rdmishra.auth.Entity.Provider;
import com.rdmishra.auth.Entity.User;
import com.rdmishra.auth.Exception.ResourcesNotFoundException;
import com.rdmishra.auth.Helper.UserHelper;
import com.rdmishra.auth.Repository.UserRepo;
import com.rdmishra.auth.Services.UserService;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServicesImpl implements UserService {

    private final UserRepo userRepo;
    private final Cloudinary cloudinary;
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDTO cecreateUser(UserDTO userDTO) {

        // Noraml Checking
        if (userDTO.getEmail() == null || userDTO.getEmail().isEmpty()) {
            throw new IllegalArgumentException("Email Is Required ");
        }
        if (userRepo.existsByEmail(userDTO.getEmail())) {
            throw new IllegalArgumentException("Email Already Exixt By Another Account ");
        }

        // Convert DTO to USER
        User user = modelMapper.map(userDTO, User.class);
        user.setProvider(userDTO.getProvider() != null ? userDTO.getProvider() : Provider.LOCAL);
        // save user
        User savedUser = userRepo.save(user);
        // return covert dto to user
        return modelMapper.map(savedUser, UserDTO.class);
    }

    @Override
    public UserDTO getUserByEmailId(String email) {
        User user = userRepo.findByEmail(email)
                .orElseThrow(() -> new ResourcesNotFoundException("User not found Enter Correct Email"));
        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    public UserDTO updateUser(UserDTO userDTO, String userId) {

        UUID usid = UserHelper.parseUUID(userId);
        User exixtUser = userRepo.findById(usid)
                .orElseThrow(() -> new ResourcesNotFoundException("User not found Enter Correct Email"));
        if (userDTO.getName() != null && !userDTO.getName().trim().isEmpty()) {
            exixtUser.setName(userDTO.getName());
        }
        if (userDTO.getEnable() != null) {
            exixtUser.setEnable(userDTO.getEnable());
        }
        if (userDTO.getName() != null)
            exixtUser.setName(userDTO.getName());
        if (userDTO.getPassword() != null)
            exixtUser.setPassword(userDTO.getPassword());
        if (userDTO.getProvider() != null)
            exixtUser.setProvider(userDTO.getProvider());
        if (userDTO.getImageUrl() != null)
            exixtUser.setImageUrl(userDTO.getImageUrl());

        exixtUser.setUpdateAt(Instant.now());
        User updateUser = userRepo.save(exixtUser);

        return modelMapper.map(updateUser, UserDTO.class);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        UUID uid = UserHelper.parseUUID(userId);
        userRepo.delete(userRepo.findById(uid)
                .orElseThrow(() -> new ResourcesNotFoundException("User not found Enter Correct Email")));
        // return modelMapper.map(userHelper, getClass())
    }

    @Override
    public UserDTO getUserById(String userId) {

        User user = userRepo.findById(UserHelper.parseUUID(userId))
                .orElseThrow(() -> new ResourcesNotFoundException("User not found Enter Correct Email"));
        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    @Transactional
    public Iterable<UserDTO> getAllUser() {
        return userRepo
                .findAll()
                .stream()
                .map(user -> modelMapper.map(user, UserDTO.class))
                .toList();
    }

    @Override
    public UserDTO updaetProfileImage(MultipartFile file, String email) {

        if (file == null || file.isEmpty()) {
            throw new RuntimeException("Image file is required");
        }

        if (!file.getContentType().startsWith("image/")) {
            throw new RuntimeException("Only image files allowed");
        }

        if (file.getSize() > 2_000_000) {
            throw new RuntimeException("Image must be less than 2MB");
        }

        User user = userRepo.findByEmail(email)
                .orElseThrow(() -> new ResourcesNotFoundException("User not found Enter Correct Email"));

        try {
            // 🔥 Delete old image
            if (user.getImageUrl() != null && user.getImageUrl().contains("cloudinary")) {
                String publicID = extractPublicId(user.getImageUrl());
                cloudinary.uploader().destroy(publicID, Map.of());
            }

            // 🔥 Upload new image
            Map uploadResult = cloudinary.uploader().upload(
                    file.getBytes(),
                    Map.of(
                            "folder", "profile-images",
                            "resource_type", "image"));

            user.setImageUrl(uploadResult.get("secure_url").toString());
            user.setUpdateAt(Instant.now());

            userRepo.save(user);

            return modelMapper.map(user, UserDTO.class);

        } catch (Exception e) {
            throw new RuntimeException("Image update failed");
        }

    }

    private String extractPublicId(String imageUrl) {
        String[] parts = imageUrl.split("/");
        String fileName = parts[parts.length - 1];
        return "profile-images/" + fileName.substring(0, fileName.lastIndexOf("."));
    }
}
