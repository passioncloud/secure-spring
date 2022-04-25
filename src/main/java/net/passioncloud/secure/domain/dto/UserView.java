package net.passioncloud.secure.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserView {
    private Long id;
    private String email;
}
