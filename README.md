# Backend for a Password saver App using FastAPI, SQLite and Python

This repo has the code for a Password saver App Backend. It exposes the below REST API endpoints. This app allows you to store passwords, which are fully encrypted in the Database. To access any of the below endpoint the Admin password must be used, the default password 
is ADMIN or ADMIN1, please be sure to change it as soon as you setup.

* PUT /updatePasswordAdmin
  
  > This endpoint allows you to change the Admin password, which needs to be used to do any of the other API operation. As a reminder, please change the password as soon as the app is setup for the first time. The password is hashed with Static and Dynamic salts.<br><br>
  > The POST Body is
  > ```
  > {
  > "oldPassword": "<OLD_ADMIN_PASSWORD>",
  > "newPassword": "<NEW_ADMIN_PASSWORD>"
  > }
  > ```

* POST /addLoginDetail
  
  > This endpoint allows you to add a login detail into the Database.<br><br>
  > The POST Body is
  > ```
  > {
  >"adminPassword": "<ADMIN_PASSWORD>",
  >"domain": "<DOMAIN_OF_THE_WEBSITE>",
  >"userID": "<YOUR_USERID_FOR_THE_DOMAIN>",
  >"password": "<YOUR_PASSWORD_FOR_THE_DOMAIN>"
  >}
  > ```
  
* POST /getPassword

  > This endpoint allows you get the password of a domain. It requires a query param to be sent.<br><br>
  > The Query Parameter is
  > ```
  > ?domain=<DOMAIN_OF_THE_WEBSITE>
  > ```
  > The POST Body is
  > ```
  > {
  >"adminPassword": "<ADMIN_PASSWORD>"
  >}
  > ```
  
* POST /getUserID
  
  > This endpoint allows you get the UserID of a domain. It requires a query param to be sent.<br><br>
  > The Query Parameter is
  > ```
  > ?domain=<DOMAIN_OF_THE_WEBSITE>
  > ```
  > The POST Body is
  > ```
  > {
  >"adminPassword": "<ADMIN_PASSWORD>"
  >}
  > ```
  
* POST /getCredentials
  
  > This endpoint allows you get the credentials, UserID and Password, of a domain. It requires a query param to be sent.<br><br>
  > The Query Parameter is
  > ```
  > ?domain=<DOMAIN_OF_THE_WEBSITE>
  > ```
  > The POST Body is
  > ```
  > {
  >"adminPassword": "<ADMIN_PASSWORD>"
  >}
  > ```
  
* POST /getAllCredentials
  
  > This endpoint allows you to get all the credentials, UserID and Password, of all the domains in the Database.<br><br>
  > The POST Body is
  > ```
  > {
  >"adminPassword": "<ADMIN_PASSWORD>"
  >}
  > ```
  
* PUT /updateCredentials
  
  > This endpoint allows you to update either the UserID or Password or both of a domain. It requires a query param to be sent.<br><br>
  > The Query Parameter is
  > ```
  > ?domain=<DOMAIN_OF_THE_WEBSITE>
  > ```
  > The PUT Body is
  > ```
  > {
  > "adminPassword": "<ADMIN_PASSWORD>",
  > "userID": "<NEW_USER_ID>",
  > "password": "<NEW_PASSWORD>"
  >}
  > ```
  
* DELETE /deleteCredentials
  > This endpoint allows you to delete the entry for a Domain from the Database. It requires a query param to be sent.<br><br>
  > The Query Parameter is
  > ```
  > ?domain=<DOMAIN_OF_THE_WEBSITE>
  > ```
  > The DELETE Body is
  > ```
  > {
  >"adminPassword": "<ADMIN_PASSWORD>"
  >}
  > ```

To run it in Dev mode, use the FastAPI run command

```console
fastapi dev .\index.py
```

Once the app is started locally, the below URL's will be available 

```
API Endpoint URL : http://127.0.0.1:8000 
Generated API Docs URL : http://127.0.0.1:8000/docs
```
