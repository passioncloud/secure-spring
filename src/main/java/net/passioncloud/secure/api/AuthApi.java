package net.passioncloud.secure.api;


import lombok.RequiredArgsConstructor;
import net.passioncloud.secure.domain.dto.AuthRequest;
import net.passioncloud.secure.domain.dto.CreateUserRequest;
import net.passioncloud.secure.domain.dto.UserView;
import net.passioncloud.secure.domain.exception.UnauthorizedException;
import net.passioncloud.secure.domain.model.User;
import net.passioncloud.secure.service.UserService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.time.Instant;
import java.util.stream.Collectors;

@RestController
@RequestMapping(path="api/public")
@RequiredArgsConstructor
public class AuthApi {

    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;
    private final UserService userService;

    @PostMapping("login")
    public ResponseEntity<UserView> login(@RequestBody @Valid AuthRequest request) throws BadCredentialsException {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(request.email(), request.password()));
            User user = (User) authentication.getPrincipal();
            Instant now = Instant.now();
            long expiryMillis = 24 * 60 * 60 * 1000L; // one day
            expiryMillis = 60 * 1000L; // one minute
            String scope = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));

            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("passioncloud.net") // TODO should  be reversed
                    .issuedAt(now)
                    .expiresAt(now.plusMillis(expiryMillis))
                    .subject(String.format("%s,%s", user.getId(), user.getUsername()))
                    .claim("roles", scope)
                    .build();

            String token = this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
            return ResponseEntity.ok()
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .body(UserView.fromModel(user));
    }

    @PostMapping(path="register")
    public UserView register(@RequestBody @Valid CreateUserRequest request) {
        return userService.create(request);
    }
}
