package com.test.api.Response;

public class LoginResponse
{
    private Long id;
    private String token;
    private String type = "Bearer";

    public LoginResponse(String accessToken)
    {
        this.token = accessToken;
    }

    public LoginResponse(Long id, String token)
    {
        this.id = id;
        this.token = token;
    }

    public Long getId()
    {
        return id;
    }

    public void setId(Long id)
    {
        this.id = id;
    }

    public String getAccessToken()
    {
        return token;
    }

    public void setAccessToken(String accessToken)
    {
        this.token = accessToken;
    }
}
