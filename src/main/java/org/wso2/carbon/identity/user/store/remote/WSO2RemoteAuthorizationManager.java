package org.wso2.carbon.identity.user.store.remote;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.user.store.remote.internal.ConfigurationContextUtil;
import org.wso2.carbon.um.ws.api.stub.RemoteAuthorizationManagerServiceStub;
import org.wso2.carbon.um.ws.api.stub.UserStoreExceptionException;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.AuthorizationManager;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;

import java.rmi.RemoteException;
import java.util.Map;

public class WSO2RemoteAuthorizationManager implements AuthorizationManager {
    private RemoteAuthorizationManagerServiceStub authorizationManager;
    private RealmConfiguration configuration;
    private static final Log log = LogFactory.getLog(WSO2RemoteAuthorizationManager.class);


    public WSO2RemoteAuthorizationManager(RealmConfiguration realmConfig, Map<String, Object> properties, ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId) throws UserStoreException, AxisFault {
        this.configuration = realmConfig;
        getClient(realmConfig);

    }

    private void getClient(RealmConfiguration realmConfig) throws AxisFault {
        ConfigurationContext configurationContext = ConfigurationContextUtil.getInstance().getContext();


        String serverURL = realmConfig.getUserStoreProperty(WSO2RemoteUserStoreManger.SERVER_URLS);
        String userName = realmConfig.getUserStoreProperty(WSO2RemoteUserStoreManger.REMOTE_USER_NAME);
        String password = realmConfig.getUserStoreProperty(WSO2RemoteUserStoreManger.PASSWORD);

        try {
            this.authorizationManager = new RemoteAuthorizationManagerServiceStub(configurationContext, serverURL + "/RemoteAuthorizationManagerService");
        } catch (AxisFault axisFault) {
            log.fatal("Failed to initialize RemoteAuthorizationManagerService client", axisFault);
            throw axisFault;
        }
        HttpTransportProperties.Authenticator authenticator = new HttpTransportProperties.Authenticator();
        authenticator.setUsername(userName);
        authenticator.setPassword(password);
        authenticator.setPreemptiveAuthentication(true);
        ServiceClient client = this.authorizationManager._getServiceClient();
        Options option = client.getOptions();
        option.setManageSession(true);
        option.setProperty(HTTPConstants.AUTHENTICATE, authenticator);


    }

    @Override
    public boolean isUserAuthorized(String s, String s1, String s2) throws UserStoreException {
        boolean isAuthorized = false;

        try {
            isAuthorized = authorizationManager.isUserAuthorized(s, s1, s2);

        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation isUserAuthorized failure ", e);
            throw new UserStoreException(e);
        }
        return isAuthorized;
    }

    @Override
    public boolean isRoleAuthorized(String roleName, String resourceId, String action) throws UserStoreException {
        boolean isAuthorized = false;

        try {
            isAuthorized = authorizationManager.isRoleAuthorized(roleName, resourceId, action);

        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation isRoleAuthorized failure ", e);
            throw new UserStoreException(e);
        }
        return isAuthorized;
    }

    @Override
    public String[] getAllowedRolesForResource(String resourceId, String action) throws UserStoreException {

        try {
            return authorizationManager.getAllowedRolesForResource(resourceId, action);
        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation getAllowedRolesForResource failure ", e);
            throw new UserStoreException(e);
        }
    }

    @Override
    public String[] getExplicitlyAllowedUsersForResource(String resourceId, String action) throws UserStoreException {
        log.info("getExplicitlyAllowedUsersForResource" + resourceId + action);
        try {
            return authorizationManager.getExplicitlyAllowedUsersForResource(resourceId, action);
        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation getExplicitlyAllowedUsersForResource failure ", e);
            throw new UserStoreException(e);
        }
    }

    @Override
    public String[] getDeniedRolesForResource(String resourceId, String action) throws UserStoreException {
        try {
            return authorizationManager.getDeniedRolesForResource(resourceId, action);
        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation getDeniedRolesForResource failure ", e);
            throw new UserStoreException(e);
        }
    }

    @Override
    public String[] getExplicitlyDeniedUsersForResource(String resourceId, String action) throws UserStoreException {
        try {
            return authorizationManager.getExplicitlyDeniedUsersForResource(resourceId, action);
        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation getExplicitlyDeniedUsersForResource failure ", e);
            throw new UserStoreException(e);
        }
    }

    @Override
    public String[] getAllowedUIResourcesForUser(String userName, String permissionRootPath) throws UserStoreException {
        try {
            return authorizationManager.getAllowedUIResourcesForUser(userName, permissionRootPath);
        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation getAllowedUIResourcesForUser failure ", e);
            throw new UserStoreException(e);
        }
    }

    @Override
    public void authorizeRole(String roleName, String resourceId, String action) throws UserStoreException {
        try {
            authorizationManager.authorizeRole(roleName, resourceId, action);
        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation authorizeRole failure ", e);
            throw new UserStoreException(e);
        }
    }

    @Override
    public void denyRole(String roleName, String resourceId, String action) throws UserStoreException {
        try {
            authorizationManager.denyRole(roleName, resourceId, action);
        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation denyRole failure ", e);
            throw new UserStoreException(e);
        }
    }

    @Override
    public void authorizeUser(String userName, String resourceId, String action) throws UserStoreException {
        try {
            authorizationManager.authorizeUser(userName, resourceId, action);
        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation authorizeUser failure ", e);
            throw new UserStoreException(e);
        }
    }

    @Override
    public void denyUser(String userName, String resourceId, String action) throws UserStoreException {
        try {
            authorizationManager.denyUser(userName, resourceId, action);
        } catch (RemoteException e) {
            log.error("Remote failure ", e);
            throw new UserStoreException(e);
        } catch (UserStoreExceptionException e) {
            log.error("Remote userstore operation denyUser failure ", e);
            throw new UserStoreException(e);
        }
    }

    @Override
    public void clearResourceAuthorizations(String resourceId) throws UserStoreException {
        //super.clearResourceAuthorizations(resourceId);
    }

    @Override
    public void clearRoleAuthorization(String roleName, String resourceId, String action) throws UserStoreException {
        //super.clearRoleAuthorization(roleName, resourceId, action);
    }

    @Override
    public void clearUserAuthorization(String userName, String resourceId, String action) throws UserStoreException {
        // super.clearUserAuthorization(userName, resourceId, action);
    }

    @Override
    public void clearRoleActionOnAllResources(String roleName, String action) throws UserStoreException {
        // super.clearRoleActionOnAllResources(roleName, action);
    }

    @Override
    public void clearRoleAuthorization(String roleName) throws UserStoreException {
        // super.clearRoleAuthorization(roleName);
    }

    @Override
    public void clearUserAuthorization(String userName) throws UserStoreException {
        // super.clearUserAuthorization(userName);
    }

    @Override
    public void resetPermissionOnUpdateRole(String roleName, String newRoleName) throws UserStoreException {
        //super.resetPermissionOnUpdateRole(roleName, newRoleName);
    }


    @Override
    public int getTenantId() throws UserStoreException {
        return this.configuration.getTenantId();
    }

    @Override
    public String[] normalizeRoles(String[] roles) {
        return roles;
    }


}
