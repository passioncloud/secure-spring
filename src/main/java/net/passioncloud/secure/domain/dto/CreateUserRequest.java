package net.passioncloud.secure.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.util.HashSet;
import java.util.Set;


@Data
@AllArgsConstructor
public class CreateUserRequest {
    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;
    @NotBlank
    private String rePassword;

    private Set<String> authorities;

    public CreateUserRequest(
            String email, String password, String rePassword
    ) {
        this(email, password, rePassword, new HashSet<>());
    }

    public CreateUserRequest(
            String email, String password
    ) {
        this(email, password, password, new HashSet<>());
    }

}
