# TerminalApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**auth**](TerminalApi.md#auth) | **GET** /term/auth | Performs user authorization by username and password
[**cd**](TerminalApi.md#cd) | **GET** /term/cd | Change current directory
[**kill**](TerminalApi.md#kill) | **POST** /term/kill | Privileged operation. Ending another user&#39;s session
[**logout**](TerminalApi.md#logout) | **POST** /term/logout | Sign Out
[**ls**](TerminalApi.md#ls) | **GET** /term/ls | List current directory
[**who**](TerminalApi.md#who) | **GET** /term/who | Issuing a list of registered users indicating their current directory


<a name="auth"></a>
# **auth**
> AuthResponse auth(username, password)

Performs user authorization by username and password

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **username** | **String**|  | [default to null]
 **password** | **String**|  | [default to null]

### Return type

[**AuthResponse**](../Models/AuthResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="cd"></a>
# **cd**
> CdResponse cd(dir)

Change current directory

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **dir** | **String**|  | [default to null]

### Return type

[**CdResponse**](../Models/CdResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="kill"></a>
# **kill**
> kill(username)

Privileged operation. Ending another user&#39;s session

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **username** | **String**|  | [default to null]

### Return type

null (empty response body)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

<a name="logout"></a>
# **logout**
> logout()

Sign Out

### Parameters
This endpoint does not need any parameter.

### Return type

null (empty response body)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

<a name="ls"></a>
# **ls**
> List ls()

List current directory

### Parameters
This endpoint does not need any parameter.

### Return type

[**List**](../Models/string.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="who"></a>
# **who**
> Map who()

Issuing a list of registered users indicating their current directory

### Parameters
This endpoint does not need any parameter.

### Return type

[**Map**](../Models/string.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

