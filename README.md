# Remote User-Store Manager
This is a usermanager for WSO2 products that can use other WSO2 instance as a userstore

## Configurations
Build the maven project and copy the jar to WSO2_HOME/repository/components/dropins. Add following configurations to WSO2_HOME/repository/conf/user-mgt.xml

#### User manager configuration 

```xml
<UserStoreManager class="org.wso2.carbon.identity.user.store.remote.WSO2RemoteUserStoreManger">
   <Property name="TenantManager">org.wso2.carbon.user.core.tenant.JDBCTenantManager</Property>
   <Property name="remoteUserName">admin</Property>
   <Property name="password">admin</Property>
   <Property name="serverUrls">https://localhost:9443/services</Property>
   <Property name="PasswordJavaScriptRegEx">^[\S]{5,30}$</Property>
   <Property name="UserNameJavaScriptRegEx">^[\S]{3,30}$</Property>
   <Property name="RoleNameJavaScriptRegEx">^[\S]{3,30}$</Property>
   <Property name="Disabled">false</Property>
   <Property name="ReadGroups">true</Property>
   <Property name="WriteGroups">true</Property>
   <Property name="Description"/>
</UserStoreManager>
```

#### Authorization manager configuration

```xml
<AuthorizationManager class="org.wso2.carbon.identity.user.store.remote.WSO2RemoteAuthorizationManager">
```
