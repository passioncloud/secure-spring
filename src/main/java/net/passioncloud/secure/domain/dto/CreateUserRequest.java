package net.passioncloud.secure.domain.dto;

import net.passioncloud.secure.domain.model.User;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

public record CreateUserRequest(
        @NotBlank
        @Email
        String email,
        @NotBlank String password) {

    public User createUser() {
        var user = new User();
        user.setEmail(email);
        return user;
    }
}
