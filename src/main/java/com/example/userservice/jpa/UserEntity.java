package com.example.userservice.jpa;

import jakarta.persistence.*;
import lombok.Data;

import static jakarta.persistence.GenerationType.*;

@Data
@Entity
@Table(name = "users")
@SequenceGenerator(
        name = "USER_SEQ_GENERATOR",
        sequenceName = "USERS_SEQ",
        initialValue = 1,
        allocationSize = 1)
public class UserEntity {
    @Id
    @GeneratedValue(strategy = SEQUENCE,
            generator="USER_SEQ_GENERATOR")
    private Long id;
    @Column(nullable = false, length = 50, unique = true)
    private String email;
    @Column(nullable = false, length = 50)
    private String name;
    @Column(name = "userid", unique = true)
    private String userId;
    @Column(name = "encryptedpwd",nullable = false, unique = true)
    private String encryptedPwd;
}
