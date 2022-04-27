package net.passioncloud.secure.domain.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;

public record AuthRequest (
        @NotNull
        @Email
        String email,
        @NotNull
        String password
) {}
