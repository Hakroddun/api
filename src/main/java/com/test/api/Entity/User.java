package com.test.api.Entity;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.Set;

@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = {
                "username"
        })
})
public class User
{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(min=3, max = 50)
    private String username;

    @NotBlank
    @Size(min=10, max = 10)
    private String phone;

    @NotBlank
    @Size(min=6, max = 100)
    private String password;

    private String jwtToken;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles;

    public User()
    {
    }

    public User(Long id, String phone)
    {
        this.id = id;
        this.phone = phone;
    }

    public User(String username, String password)
    {
        this.username = username;
        this.password = password;
    }

    public User(Long id, String phone, String jwtToken)
    {
        this.id = id;
        this.phone = phone;
        this.jwtToken = jwtToken;
    }

    public User(String username, String phone, String password)
    {
        this.username = username;
        this.phone = phone;
        this.password = password;
    }

    public Long getId()
    {
        return id;
    }

    public void setId(Long id)
    {
        this.id = id;
    }

    public String getUsername()
    {
        return username;
    }

    public void setUsername(String username)
    {
        this.username = username;
    }

    public String getPhone()
    {
        return phone;
    }

    public void setPhone(String phone)
    {
        this.phone = phone;
    }

    public String getPassword()
    {
        return password;
    }

    public void setPassword(String password)
    {
        this.password = password;
    }

    public String getJwtToken()
    {
        return jwtToken;
    }

    public void setJwtToken(String jwtToken)
    {
        this.jwtToken = jwtToken;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

}
