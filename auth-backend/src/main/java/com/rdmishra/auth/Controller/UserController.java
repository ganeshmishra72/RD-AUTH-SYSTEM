package com.rdmishra.auth.Controller;

import java.security.Principal;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.rdmishra.auth.DTO.UserDTO;
import com.rdmishra.auth.Services.UserService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/v1/users")
@AllArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    public ResponseEntity<UserDTO> createUser(@RequestBody UserDTO userDTO) {

        UserDTO data = userService.cecreateUser(userDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(data);
    }

    @GetMapping
    public ResponseEntity<Iterable<UserDTO>> getUsers() {
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(userService.getAllUser());
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<UserDTO> getUserByEmail(@PathVariable("email") String email) {
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(userService.getUserByEmailId(email));
    }

    @DeleteMapping("{userId}")
    public ResponseEntity<Void> deleteuser(@PathVariable("userId") String userId) {
        userService.deleteUser(userId);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    @GetMapping("/id/{userId}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable("userId") String userId) {
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(userService.getUserById(userId));
    }

    @PutMapping("/id/{userId}")
    public ResponseEntity<UserDTO> updateUser(@RequestBody UserDTO userDTO, @PathVariable("userId") String userId) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.updateUser(userDTO, userId));
    }

    @PostMapping("/profile/image")
    public ResponseEntity<UserDTO> updateImage(
            @RequestParam MultipartFile file,
            Principal principal) {
        return ResponseEntity.ok(
                userService.updaetProfileImage(file, principal.getName()));
    }
}
