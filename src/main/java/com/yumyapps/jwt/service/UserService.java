package com.yumyapps.jwt.service;

import com.yumyapps.jwt.exception.domain.*;
import com.yumyapps.jwt.models.User;

import java.io.IOException;
import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistException, EmailExistException;

    List<User> getUsers();

    User findUserByUsername(String username);

    User findUserByEmail(String email);



    User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername,
                    String newEmail, String role, boolean isNonLocked, boolean isActive)
            throws UserNotFoundException, UsernameExistException, IOException, NotAnImageFileException, EmailExistException;


    void deleteUser(Long id) throws IOException;
    void deleteUser(String username) throws IOException;

    void resetPassword(String email) throws EmailNotFoundException, UserNotFoundException;
}
