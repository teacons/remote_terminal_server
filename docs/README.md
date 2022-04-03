# Documentation for Terminal Api

<a name="documentation-for-api-endpoints"></a>
## Documentation for API Endpoints

All URIs are relative to *http://localhost:8080*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*TerminalApi* | [**auth**](Apis/TerminalApi.md#auth) | **GET** /term/auth | Performs user authorization by username and password
*TerminalApi* | [**cd**](Apis/TerminalApi.md#cd) | **GET** /term/cd | Change current directory
*TerminalApi* | [**kill**](Apis/TerminalApi.md#kill) | **POST** /term/kill | Privileged operation. Ending another user's session
*TerminalApi* | [**logout**](Apis/TerminalApi.md#logout) | **POST** /term/logout | Sign Out
*TerminalApi* | [**ls**](Apis/TerminalApi.md#ls) | **GET** /term/ls | List current directory
*TerminalApi* | [**who**](Apis/TerminalApi.md#who) | **GET** /term/who | Issuing a list of registered users indicating their current directory


<a name="documentation-for-models"></a>
## Documentation for Models

 - [AuthResponse](./Models/AuthResponse.md)
 - [CdResponse](./Models/CdResponse.md)


<a name="documentation-for-authorization"></a>
## Documentation for Authorization

<a name="bearerAuth"></a>
### bearerAuth

- **Type**: HTTP basic authentication

