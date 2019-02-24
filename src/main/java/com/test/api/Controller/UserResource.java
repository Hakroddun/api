package com.test.api.Controller;

import com.google.gson.Gson;
import com.test.api.Entity.Role;
import com.test.api.Entity.RoleName;
import com.test.api.Entity.User;
import com.test.api.Repository.UserRepository;
import com.test.api.Request.LoginForm;
import com.test.api.Request.UserForm;
import com.test.api.Response.JwtResponse;
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
import java.util.*;

@RestController
@RequestMapping("/api")
public class UserResource
{
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtProvider jwtProvider;

    @PutMapping(value = "/users", consumes = "application/json")
    public ResponseEntity<String> saveUser(@RequestBody UserForm userFormRequest)
    {
        if(userRepository.existsByUsername(userFormRequest.getUsername()))
        {
            return new ResponseEntity<String>("Fail -> Username is already taken!", HttpStatus.BAD_REQUEST);
        }

        User user = new User(userFormRequest.getUsername(), userFormRequest.getPhone(), encoder.encode(userFormRequest.getPassword()));

        Set<Role> roles = new HashSet<>();
        roles.add(new Role((long) 1,RoleName.ROLE_USER));
        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok().body("User created successfully!");
    }

    @GetMapping(value = "/users", produces = "application/json")
    public String retrieveAllUsers()
    {
        return new Gson().toJson(userRepository.findAll(),List.class);
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest, HttpServletResponse response)
    {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );


        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtProvider.generateJwtToken(authentication);
        User user = userRepository.findByUsername(loginRequest.getUsername()).orElseThrow(() ->new UsernameNotFoundException("User Not Found with -> username: " + loginRequest.getUsername()));
        user.setJwtToken(jwt);
        userRepository.save(user);

        response.addHeader("Token",jwt);
        return ResponseEntity.ok(new JwtResponse(jwt));
    }

    @GetMapping("/users/active")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String userAccess() {

        List<User> users = userRepository.findAllWithToken();
        List<UserResponse> validUsers = new ArrayList<>();
        for(User user : users)
        {
            if(jwtProvider.validateJwtToken(user.getJwtToken()))
            {
                validUsers.add(new UserResponse(user.getId(),user.getPhone()));
            }
        }
        return new Gson().toJson(validUsers,List.class);
    }

    @GetMapping(value = "/logout/{id}")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<?> logout(@PathVariable("id") Long id, HttpServletResponse response)
    {
        User user = userRepository.findById(id).orElseThrow(() -> new UsernameNotFoundException("User Not Found with -> username : " + id));

        String token = user.getJwtToken();

        user.setJwtToken(null);
        userRepository.save(user);

        response.addHeader("Token",token);
        return ResponseEntity.ok(new JwtResponse(token.toString()));
    }

}
