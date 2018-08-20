/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.user.store.remote;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.description.TransportOutDescription;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.um.ws.api.WSUserStoreManager;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.RoleContext;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.JDBCRealmUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.Secret;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

public class WSO2RemoteUserStoreManger extends AbstractUserStoreManager {

    private static final String CONNECTION_REFUSED = "Connection refused";
    private static final Log log = LogFactory.getLog(WSO2RemoteUserStoreManger.class);
    public static final String SERVER_URLS = "serverUrls";
    public static final String REMOTE_USER_NAME = "remoteUserName";
    public static final String PASSWORD = "password";
    protected DataSource jdbcds = null;
    private WSUserStoreManager remoteUserStore;
    private String domainName;
    private UserStoreManager secondaryUserStoreManager;
    private Map<String, WSUserStoreManager> remoteServers = new HashMap<String, WSUserStoreManager>();
    private static final String REMOTE_ERROR_MSG = "Error occured while getting remote store value: ignoring the error";

    public WSO2RemoteUserStoreManger(){

    }

    /**
     * @param realmConfig
     * @param properties
     * @throws Exception
     */
    public WSO2RemoteUserStoreManger(RealmConfiguration realmConfig, Map properties)
            throws Exception {

        ConfigurationContext configurationContext = ConfigurationContextFactory
                .createDefaultConfigurationContext();

        Map<String, TransportOutDescription> transportsOut = configurationContext
                .getAxisConfiguration().getTransportsOut();
        for (TransportOutDescription transportOutDescription : transportsOut.values()) {
            transportOutDescription.getSender().init(configurationContext, transportOutDescription);
        }

        String[] serverUrls = realmConfig.getUserStoreProperty(SERVER_URLS).split(",");

        for (int i = 0; i < serverUrls.length; i++) {
            remoteUserStore = new WSUserStoreManager(
                    realmConfig.getUserStoreProperty(REMOTE_USER_NAME),
                    realmConfig.getUserStoreProperty(PASSWORD), serverUrls[i],
                    configurationContext);

            if (log.isDebugEnabled()) {
                log.debug("Remote Servers for User Management : " + serverUrls[i]);
            }

            remoteServers.put(serverUrls[i], remoteUserStore);
        }

        this.realmConfig = realmConfig;
        domainName = realmConfig.getUserStoreProperty(UserStoreConfigConstants.DOMAIN_NAME);

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED) != null) {
            readGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED));
        }

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED) != null) {
            writeGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED));
        } else {
            if (!isReadOnly()) {
                writeGroupsEnabled = true;
            }
        }









        log.info("CustomUserStoreManager initialized...");

    }

    public WSO2RemoteUserStoreManger(RealmConfiguration realmConfig, Map<String, Object> properties,
                                     ClaimManager claimManager, ProfileConfigurationManager profileManager, org.wso2.carbon.user.core.UserRealm realm,
                                     Integer tenantId) throws Exception {
        this(realmConfig, properties);

        this.claimManager = claimManager;
        this.tenantId = tenantId;

        try {
            jdbcds = loadUserStoreSpacificDataSoruce();

            if (jdbcds == null) {
                jdbcds = (DataSource) properties.get(UserCoreConstants.DATA_SOURCE);
            }
            if (jdbcds == null) {
                jdbcds = DatabaseUtil.getRealmDataSource(realmConfig);
                properties.put(UserCoreConstants.DATA_SOURCE, jdbcds);
            }

            if (log.isDebugEnabled()) {
                log.debug("The jdbcDataSource being used by JDBCUserStoreManager :: "
                        + jdbcds.hashCode());
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Loading JDBC datasource failed", e);
            }
        }

        dataSource = (DataSource) properties.get(UserCoreConstants.DATA_SOURCE);
        if (dataSource == null) {
            dataSource = DatabaseUtil.getRealmDataSource(realmConfig);
        }
        if (dataSource == null) {
            throw new UserStoreException("User Management Data Source is null");
        }

        properties.put(UserCoreConstants.DATA_SOURCE, dataSource);


        realmConfig.setUserStoreProperties(JDBCRealmUtil.getSQL(realmConfig
                .getUserStoreProperties()));

        this.persistDomain();
        doInitialSetup();
        if (realmConfig.isPrimary()) {
            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()),
                    !isInitSetupDone());
        }

        initUserRolesCache();

        if (log.isDebugEnabled()) {
            log.debug("Ended " + System.currentTimeMillis());
        }
        /* Initialize user roles cache as implemented in AbstractUserStoreManager */
    }


    public WSO2RemoteUserStoreManger(RealmConfiguration realmConfig, ClaimManager claimManager,
                                     ProfileConfigurationManager profileManager) throws Exception {
        this(realmConfig, new HashMap());
        // checkRequiredUserStoreConfiguration();
    }

    /**
     * @param realmConfig
     * @param tenantId
     * @throws UserStoreException
     */
    public WSO2RemoteUserStoreManger(RealmConfiguration realmConfig, int tenantId) throws Exception {
        this(realmConfig, new HashMap());
    }

    /**
     * This constructor is used by the support IS
     *
     * @param ds
     * @param realmConfig
     * @param tenantId
     * @param addInitData
     * @param tenantId
     */
    public WSO2RemoteUserStoreManger(DataSource ds, RealmConfiguration realmConfig, int tenantId,
                                     boolean addInitData) throws Exception {

        this(realmConfig, new HashMap());
    }

    /**
     * This constructor to accommodate PasswordUpdater called from chpasswd script
     *
     * @param ds
     * @param realmConfig
     * @throws UserStoreException
     */
    public WSO2RemoteUserStoreManger(DataSource ds, RealmConfiguration realmConfig)
            throws Exception {

        this(realmConfig, new HashMap());
    }


    /**
     * @param realmConfig
     * @param properties
     * @param claimManager
     * @param profileManager
     * @param realm
     * @param tenantId
     * @param skipInitData
     * @throws UserStoreException
     */
    public WSO2RemoteUserStoreManger(RealmConfiguration realmConfig, Map<String, Object> properties,
                                     ClaimManager claimManager, ProfileConfigurationManager profileManager, org.wso2.carbon.user.core.UserRealm realm,
                                     Integer tenantId, boolean skipInitData) throws Exception {
        this(realmConfig, properties);
    }

    @Override
    protected Map<String, String> getUserPropertyValues(String userName, String[] claims, String profileName) throws UserStoreException {
        Map<String, String> claimValue = new HashMap<String, String>();

        try {
            claimValue = remoteUserStore.getUserClaimValues(userName, claims, profileName);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        claimValue = remoteStore.getValue().getUserClaimValues(userName, claims,
                                profileName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return claimValue;
    }

    @Override
    protected boolean doCheckExistingRole(String roleName) throws UserStoreException {
        boolean rolesExists = false;
        try {
            rolesExists = remoteUserStore.isExistingRole(roleName);

        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        rolesExists = remoteStore.getValue().isExistingRole(roleName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return rolesExists;
    }

    @Override
    protected RoleContext createRoleContext(String s) throws UserStoreException {
        return null;
    }

    @Override
    protected boolean doCheckExistingUser(String userName) throws UserStoreException {
        boolean usersExists = false;
        try {
            usersExists = remoteUserStore.isExistingUser(userName);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        usersExists = remoteStore.getValue().isExistingUser(userName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return usersExists;
    }

    @Override
    protected String[] getUserListFromProperties(String claim, String claimValue, String profileName) throws UserStoreException {
        String[] users = new String[0];
        try {
            users = remoteUserStore.getUserList(claim, claimValue, profileName);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        users = remoteStore.getValue().getUserList(claim, claimValue, profileName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }

        if (users != null) {
            for (int i = 0; i < users.length; i++) {
                users[i] = domainName + "/" + users[i];
            }
        } else {
            return new String[0];
        }
        return users;
    }

    @Override
    protected boolean doAuthenticate(String userName, Object credential) throws UserStoreException {
        if (credential instanceof Secret) {
            String secretString = new String(((Secret) credential).getChars());
            return this.remoteUserStore.authenticate(userName, secretString);
        }else {
            return this.remoteUserStore.authenticate(userName, credential);
        }
    }

    @Override
    protected void doAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims, String profileName, boolean requirePasswordChange) throws UserStoreException {
        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                if (credential instanceof Secret) {
                    String secretString = new String(((Secret) credential).getChars());
                    remoteStore.getValue().addUser(userName, secretString, roleList, claims, profileName);
                } else {
                    remoteStore.getValue().addUser(userName, credential, roleList, claims, profileName);
                }
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {


                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }


    @Override
    protected void doUpdateCredential(String userName, Object newCredential, Object oldCredential) throws UserStoreException {
        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                if (newCredential instanceof Secret) {
                    String newPassowrd = new String(((Secret) newCredential).getChars());
                    String oldPassword = new String(((Secret) oldCredential).getChars());
                    remoteStore.getValue().updateCredential(userName, newPassowrd, oldPassword);
                } else {
                    remoteStore.getValue().updateCredential(userName, newCredential, oldCredential);
                }



            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {
        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                if (newCredential instanceof Secret) {
                    String newPassowrd = new String(((Secret) newCredential).getChars());
                    remoteStore.getValue().updateCredentialByAdmin(userName, newPassowrd);
                } else {
                    remoteStore.getValue().updateCredentialByAdmin(userName, newCredential);
                }


            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected void doDeleteUser(String userName) throws UserStoreException {
        String domainAwareUserName = UserCoreUtil.removeDomainFromName(userName);

        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                remoteStore.getValue().deleteUser(domainAwareUserName);
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected void doSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName) throws UserStoreException {
        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                remoteStore.getValue().setUserClaimValue(userName, claimURI, claimValue,
                        profileName);
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected void doSetUserClaimValues(String userName, Map<String, String> claims, String profileName) throws UserStoreException {
        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                remoteStore.getValue().setUserClaimValues(userName, claims, profileName);
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected void doDeleteUserClaimValue(String userName, String claimURI, String profileName) throws UserStoreException {
        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                remoteStore.getValue().deleteUserClaimValue(userName, claimURI, profileName);
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected void doDeleteUserClaimValues(String userName, String[] claims, String profileName) throws UserStoreException {
        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                remoteStore.getValue().deleteUserClaimValues(userName, claims, profileName);
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected void doUpdateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers) throws UserStoreException {
        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                remoteStore.getValue().updateUserListOfRole(roleName, deletedUsers, newUsers);
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected void doUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles) throws UserStoreException {
        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                remoteStore.getValue().updateRoleListOfUser(userName, deletedRoles, newRoles);
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected String[] doGetExternalRoleListOfUser(String userName, String tenantDomain) throws UserStoreException {
        String[] roles = null;

        try {
            roles = remoteUserStore.getRoleListOfUser(userName);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        roles = remoteStore.getValue().getRoleListOfUser(userName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        if (roles != null) {
            for (int i = 0; i < roles.length; i++) {
                roles[i] = domainName + "/" + roles[i];
            }
        } else {
            roles = new String[0];
        }
        return roles;
    }

    @Override
    protected String[] doGetSharedRoleListOfUser(String userName, String tenantDomain, String filter) throws UserStoreException {
        String[] roles = null;

        try {
            roles = remoteUserStore.getRoleListOfUser(userName);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        roles = remoteStore.getValue().getRoleListOfUser(userName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        if (roles != null) {
            for (int i = 0; i < roles.length; i++) {
                roles[i] = domainName + "/" + roles[i];
            }
        } else {
            roles = new String[0];
        }
        return roles;
    }

    @Override
    protected void doAddRole(String roleName, String[] userList, boolean isSharedRole) throws UserStoreException {

        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                remoteStore.getValue().addRole(roleName, userList , null);
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to update the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected void doDeleteRole(String roleName) throws UserStoreException {
        String domainAwareRoleName = UserCoreUtil.removeDomainFromName(roleName);

        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                remoteStore.getValue().deleteRole(domainAwareRoleName);
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected void doUpdateRoleName(String roleName, String newRoleName) throws UserStoreException {
        for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers.entrySet()
                .iterator(); iterator.hasNext(); ) {
            Entry<String, WSUserStoreManager> remoteStore = iterator.next();
            try {
                remoteStore.getValue().updateRoleName(roleName, newRoleName);
            } catch (UserStoreException e) {
                if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                    throw e;
                }
                log.error("Failed to connect to the remote server : " + remoteStore.getKey());
            }
        }
    }

    @Override
    protected String[] doGetRoleNames(String filter, int maxLimit) throws UserStoreException {
        String[] roles = null;

        try {
            roles = remoteUserStore.getRoleNames();
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        roles = remoteStore.getValue().getRoleNames();
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }

        if (roles != null) {
            for (int i = 0; i < roles.length; i++) {
                roles[i] = domainName + "/" + roles[i];
            }
        } else {
            roles = new String[0];
        }

        return roles;
    }

    @Override
    protected String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException {
        String[] users = null;

        try {
            users = remoteUserStore.listUsers(filter, maxItemLimit);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        users = remoteStore.getValue().listUsers(filter, maxItemLimit);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }

        if (users != null) {
            for (int i = 0; i < users.length; i++) {
                users[i] = domainName + "/" + users[i];
            }
        } else {
            users = new String[0];
        }

        return users;

    }

    @Override
    protected String[] doGetDisplayNamesForInternalRole(String[] strings) throws UserStoreException {
        return new String[0];
    }

    @Override
    public boolean doCheckIsUserInRole(String s, String s1) throws UserStoreException {
        return true;
    }

    @Override
    protected String[] doGetSharedRoleNames(String tenantDomain, String filter, int maxItemLimit) throws UserStoreException {
        String[] roles = null;

        try {
            roles = remoteUserStore.getRoleNames();
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        roles = remoteStore.getValue().getRoleNames();
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }

        if (roles != null) {
            for (int i = 0; i < roles.length; i++) {
                roles[i] = domainName + "/" + roles[i];
            }
        } else {
            roles = new String[0];
        }

        return roles;
    }

    @Override
    protected String[] doGetUserListOfRole(String roleName, String filter) throws UserStoreException {
        String[] users = null;

        try {
            users = remoteUserStore.getUserListOfRole(roleName);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        users = remoteStore.getValue().getUserListOfRole(roleName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }

        if (users != null) {
            for (int i = 0; i < users.length; i++) {
                users[i] = domainName + "/" + users[i];
            }
        } else {
            users = new String[0];
        }

        return users;
    }


    @Override
    public String[] getProfileNames(String userName) throws UserStoreException {
        String[] profileNames = new String[0];

        try {
            profileNames = remoteUserStore.getProfileNames(userName);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        profileNames = remoteStore.getValue().getRoleListOfUser(userName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return profileNames;
    }

    @Override
    public String[] getAllProfileNames() throws UserStoreException {
        String[] profileNames = new String[0];
        try {
            profileNames = remoteUserStore.getAllProfileNames();
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        profileNames = remoteStore.getValue().getAllProfileNames();
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return profileNames;
    }

    @Override
    public boolean isReadOnly() throws UserStoreException {
        boolean readOnly = false;
        try {
            readOnly = remoteUserStore.isReadOnly();
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        readOnly = remoteStore.getValue().isReadOnly();
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return readOnly;
    }

    @Override
    public int getUserId(String username) throws UserStoreException {
        int userId = -1;
        try {
            userId = remoteUserStore.getUserId(username);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        userId = remoteStore.getValue().getUserId(username);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return userId;
    }

    @Override
    public int getTenantId(String username) throws UserStoreException {
        int tenantId = -1;
        try {
            tenantId = remoteUserStore.getTenantId(username);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        tenantId = remoteStore.getValue().getTenantId(username);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return tenantId;
    }

    @Override
    public int getTenantId() throws UserStoreException {
        int tenantId = -1;
        try {
            tenantId = remoteUserStore.getTenantId();
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        tenantId = remoteStore.getValue().getTenantId();
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return tenantId;
    }

    @Override
    public Map<String, String> getProperties(org.wso2.carbon.user.api.Tenant tenant) throws org.wso2.carbon.user.api.UserStoreException {
        Map<String, String> properties = new HashMap<String, String>();
        try {
            properties = remoteUserStore.getProperties(tenant);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        properties = remoteStore.getValue().getProperties(tenant);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return properties;
    }

    @Override
    public boolean isMultipleProfilesAllowed() {
        return false;
    }

    @Override
    public void addRememberMe(String s, String s1) throws org.wso2.carbon.user.api.UserStoreException {

    }

    @Override
    public boolean isValidRememberMeToken(String s, String s1) throws org.wso2.carbon.user.api.UserStoreException {
        return false;
    }

    @Override
    public Properties getDefaultUserStoreProperties() {


        Properties properties = new Properties();
        Property[] mandatoryProperties = null;
        Property[] optionalProperties = null;
        Property remoteServerUserName = new Property(
                REMOTE_USER_NAME,
                "",
                "Remote Sever Username#Name of a user from the remote server, having enough privileges for user management",
                null);
        Property password = new Property(PASSWORD, "",
                "Remote Server Password#The password correspoing to the remote server " +
                        "username#encrypt",
                null);
        Property serverUrls = new Property(
                SERVER_URLS,
                "",
                "Remote Server URL(s)#Remote server URLs. e.g.: https://ca-datacenter/services,https://va-datacenter/services",
                null);
        Property disabled = new Property("Disabled", "false", "Disabled#Check to disable the user store", null);

        Property passwordJavaScriptRegEx = new Property(
                UserStoreConfigConstants.passwordJavaScriptRegEx, "^[\\S]{5,30}$",
                "Password RegEx (Javascript)#"
                        + UserStoreConfigConstants.passwordJavaScriptRegExDescription, null);
        Property usernameJavaScriptRegEx = new Property(
                UserStoreConfigConstants.usernameJavaScriptRegEx, "^[\\S]{3,30}$",
                "Username RegEx (Javascript)#"
                        + UserStoreConfigConstants.usernameJavaRegExDescription, null);
        Property roleNameJavaScriptRegEx = new Property(
                UserStoreConfigConstants.roleNameJavaScriptRegEx, "^[\\S]{3,30}$",
                "Role Name RegEx (Javascript)#"
                        + UserStoreConfigConstants.roleNameJavaScriptRegExDescription, null);

        mandatoryProperties = new Property[] {remoteServerUserName, password, serverUrls, passwordJavaScriptRegEx,
                usernameJavaScriptRegEx, roleNameJavaScriptRegEx};
        optionalProperties = new Property[] {disabled};

        properties.setOptionalProperties(optionalProperties);
        properties.setMandatoryProperties(mandatoryProperties);
        return properties;

    }

    @Override
    public Map<String, String> getProperties(Tenant tenant) throws UserStoreException {
        Map<String, String> properties = new HashMap<String, String>();
        try {
            properties = remoteUserStore.getProperties(tenant);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        properties = remoteStore.getValue().getProperties(tenant);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return properties;
    }

    @Override
    public boolean isBulkImportSupported() throws UserStoreException {
        return false;
    }

    @Override
    public RealmConfiguration getRealmConfiguration() {
        return realmConfig;
    }

    @Override
    public String[] getRoleListOfUser(String userName) throws UserStoreException {
        String[] roles = null;

        try {
            roles = remoteUserStore.getRoleListOfUser(userName);
        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        roles = remoteStore.getValue().getRoleListOfUser(userName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        if (roles != null) {
            for (int i = 0; i < roles.length; i++) {
                roles[i] = domainName + "/" + roles[i];
            }
        } else {
            roles = new String[0];
        }
        return roles;

    }


    @Override
    public boolean isExistingRole(String roleName, boolean shared) throws org.wso2.carbon.user.api.UserStoreException {
        boolean rolesExists = false;
        try {
            rolesExists = remoteUserStore.isExistingRole(roleName);

        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        rolesExists = remoteStore.getValue().isExistingRole(roleName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return rolesExists;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isExistingRole(String roleName) throws UserStoreException {
        boolean rolesExists = false;
        try {
            rolesExists = remoteUserStore.isExistingRole(roleName);

        } catch (UserStoreException e) {
            if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {
                throw e;
            }
            synchronized (this) {
                for (Iterator<Entry<String, WSUserStoreManager>> iterator = remoteServers
                        .entrySet().iterator(); iterator.hasNext(); ) {
                    Entry<String, WSUserStoreManager> remoteStore = iterator.next();
                    try {
                        rolesExists = remoteStore.getValue().isExistingRole(roleName);
                        remoteUserStore = remoteStore.getValue();
                        break;
                    } catch (UserStoreException ex) {
                        if (!CONNECTION_REFUSED.equalsIgnoreCase(e.getMessage())) {

                            if(log.isDebugEnabled()){

                                log.debug(REMOTE_ERROR_MSG,ex);

                            }

                            throw e;
                        }
                        log.error("Failed to connect to the remote server : "
                                + remoteStore.getKey());
                    }
                }
            }
        }
        return rolesExists;
    }

    private DataSource loadUserStoreSpacificDataSoruce() throws UserStoreException {
        return DatabaseUtil.createUserStoreDataSource(realmConfig);
    }

}
