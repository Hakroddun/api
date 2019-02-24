package com.test.api.Response;

public class UserResponse
{
    private Long id;
    private String phone;

    public UserResponse(Long id, String phone)
    {
        this.id = id;
        this.phone = phone;
    }

    public Long getId()
    {
        return id;
    }

    public void setId(Long id)
    {
        this.id = id;
    }

    public String getPhone()
    {
        return phone;
    }

    public void setPhone(String phone)
    {
        this.phone = phone;
    }
}
