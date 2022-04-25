package net.passioncloud.secure.service;

import lombok.RequiredArgsConstructor;
import net.passioncloud.secure.domain.dto.CreateUserRequest;
import net.passioncloud.secure.domain.dto.UserView;
import net.passioncloud.secure.domain.model.User;
import net.passioncloud.secure.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import javax.validation.ValidationException;


@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    @Transactional
    public UserView create(CreateUserRequest request) {
        if(userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new ValidationException("Email exists");
        }
        if(!request.getPassword().equals(request.getRePassword())) {
            throw new ValidationException("Passwords do not match");
        }
        User repo = new User()

    }
}
