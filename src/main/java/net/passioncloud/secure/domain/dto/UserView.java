package net.passioncloud.secure.domain.dto;


import net.passioncloud.secure.domain.model.User;


public record UserView(Long id, String email) {
    public static UserView fromModel(User user) {
        return new UserView(user.getId(), user.getEmail());
    }
}
