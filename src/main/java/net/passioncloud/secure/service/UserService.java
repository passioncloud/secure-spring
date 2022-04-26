package net.passioncloud.secure.service;

import lombok.RequiredArgsConstructor;
import net.passioncloud.secure.domain.dto.CreateUserRequest;
import net.passioncloud.secure.domain.dto.UserView;
import net.passioncloud.secure.domain.model.User;
import net.passioncloud.secure.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import javax.validation.ValidationException;


@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    @Transactional
    public UserView create(CreateUserRequest request) {
        if(userRepository.findByEmail(request.email()).isPresent()) {
            throw new ValidationException("Email exists");
        }
        User user = request.createUser();
        user.setPassword(passwordEncoder.encode(request.password()));
        user = userRepository.save(user);
        return UserView.fromModel(user);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("User with email %s not found", email)));
    }
}
