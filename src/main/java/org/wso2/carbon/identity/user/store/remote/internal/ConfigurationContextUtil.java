package org.wso2.carbon.identity.user.store.remote.internal;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.description.TransportOutDescription;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Map;

public class ConfigurationContextUtil {
    private static ConfigurationContextUtil ourInstance = new ConfigurationContextUtil();
    private ConfigurationContext context;
    private static final Log log = LogFactory.getLog(ConfigurationContextUtil.class);

    public static ConfigurationContextUtil getInstance() {
        return ourInstance;
    }

    private ConfigurationContextUtil() {

        try {
            this.context = ConfigurationContextFactory
                    .createDefaultConfigurationContext();
        } catch (Exception e) {
            log.fatal("Unable to initialize config context", e);
            return;
        }

        Map<String, TransportOutDescription> transportsOut = context
                .getAxisConfiguration().getTransportsOut();
        for (TransportOutDescription transportOutDescription : transportsOut.values()) {
            try {
                transportOutDescription.getSender().init(context, transportOutDescription);
            } catch (AxisFault axisFault) {
                log.fatal("Unable to set initialize transport sender", axisFault);
                return;
            }
        }
    }

    public ConfigurationContext getContext() {
        return this.context;
    }
}
