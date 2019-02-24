package com.test.api.Controller;

import com.test.api.Entity.Role;
import com.test.api.Entity.RoleName;
import com.test.api.Entity.User;
import com.test.api.Repository.UserRepository;
import com.test.api.Request.LoginRequest;
import com.test.api.Request.UserRequest;
import com.test.api.Response.LoginResponse;
import com.test.api.Response.LogoutResponse;
import com.test.api.Response.UserResponse;
import com.test.api.Security.Services.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class UserResource
{
    @Autowired
    private
    AuthenticationManager authenticationManager;

    @Autowired
    private
    UserRepository userRepository;

    @Autowired
    private
    PasswordEncoder encoder;

    @Autowired
    private
    JwtProvider jwtProvider;

    @PutMapping(value = "/users", consumes = "application/json")
    public ResponseEntity<?> saveUser(@RequestBody UserRequest userFormRequest)
    {
        if (userRepository.existsByUsername(userFormRequest.getUsername()))
        {
            return new ResponseEntity<>("Fail -> Username is already taken!", HttpStatus.BAD_REQUEST);
        }

        User user = new User(userFormRequest.getUsername(), userFormRequest.getPhone(), encoder.encode(userFormRequest.getPassword()));

        Set<Role> roles = new HashSet<>();
        roles.add(new Role((long) 1, RoleName.ROLE_USER));
        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok("User created successfully!");
    }

    @GetMapping(value = "/users", produces = "application/json")
    public ResponseEntity<?> retrieveAllUsers()
    {
        List<UserResponse> allUsers = userRepository.findAll().stream()
                .map(u -> new UserResponse(u.getId(), u.getPhone())).collect(Collectors.toList());
        return ResponseEntity.ok(allUsers);
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, HttpServletResponse response)
    {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtProvider.generateJwtToken(authentication);
        User user = userRepository.findByUsername(loginRequest.getUsername()).orElseThrow(() -> new UsernameNotFoundException("User Not Found with -> username: " + loginRequest.getUsername()));
        user.setJwtToken(jwt);
        userRepository.save(user);

        response.addHeader("Token", jwt);
        return ResponseEntity.ok(new LoginResponse(user.getId(), jwt));
    }

    @GetMapping("/users/active")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<?> userAccess()
    {
        List<UserResponse> validUsers = userRepository.findAllWithToken().stream()
                .filter(u -> jwtProvider.validateJwtToken(u.getJwtToken()))
                .map(vu -> new UserResponse(vu.getId(), vu.getPhone())).collect(Collectors.toList());
        return ResponseEntity.ok(validUsers);
    }

    @GetMapping(value = "/logout/{id}")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<?> logout(@PathVariable("id") Long id, HttpServletResponse response)
    {
        User user = userRepository.findById(id).orElseThrow(() -> new UsernameNotFoundException("User Not Found with -> username : " + id));

        String token = user.getJwtToken();

        user.setJwtToken(null);
        userRepository.save(user);

        response.addHeader("Token", token);
        return ResponseEntity.ok(new LogoutResponse(token));
    }

}
