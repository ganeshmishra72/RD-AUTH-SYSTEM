package com.rdmishra.auth.DTO;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.rdmishra.auth.Entity.Provider;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {
    private UUID id;
    private String name;
    private String email;
    private String password;
    private Provider provider = Provider.LOCAL;
    private Set<RoleDTO> roles = new HashSet<>();
    private String imageUrl;
    private Instant createAt = Instant.now();
    private Instant updateAt = Instant.now();
    private Boolean enable = true;
}
