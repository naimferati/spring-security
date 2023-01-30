package com.example.springsecurity.auth;

import org.springframework.stereotype.Repository;

import java.util.Optional;

public interface ApplicationUserDAO {

    Optional<ApplicationUser> selectApplicationUserByUsername(String username);

}
