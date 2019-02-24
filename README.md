# api
This is a REST API system that uses Maven, Spring Boot, Spring Security, JWT, JPA and H2.
It allows the saving of users, login and logout functionality, the retrieving of user details and retrieving users that are actively logged in. 
  
#Getting Started  
Import it as a Maven project, and run the main method in the ApiApplication class.  
Check that it starts up wihout errors.  
Import the API.postman_collection.json file into postman.  
  
#Create a user  
[PUT] /api/users  
In postman click on the Save User request.  
In Body edit the JSON object with the the username, phone number and password.  
Click send to save that user to the database.  
  
#Retrieve a list of users  
[GET] api/users  
In postman click on the Get Users request.  
Click send to retrieve a list of users in the database.  
  
#Login  
[POST] /api/login  
In postman click on the Login User request.  
In Body edit the JSON object with the username and password saved previously.  
Click send to retrieve the user's ID and Token. 
  
#Retrieve a list of active users  
[GET] /api/users/active  
In postman click on the Get Active Users request.  
In Autherization select Bearer Token.  
Copy the token recieved from logging in, into the Token field.  
Click send to retrieve a list of active users in the database.  
  
#Logout  
[GET] /api/logout/:id  
In postman click on the Logout User request.  
In the url change add the id of the user to logout after "logout/".  
In Autherization select Bearer Token.  
Copy the token recieved from logging in, into the Token field.  
Click send to logout the user and recieve the Token of the user.  
