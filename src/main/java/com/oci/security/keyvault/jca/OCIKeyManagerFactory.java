package com.oci.security.keyvault.jca;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import static java.util.logging.Level.INFO;

/**
 * The OCI Key Vault variant of the KeyManagerFactory.
 *
 * @see KeyManagerFactorySpi
 */
public final class OCIKeyManagerFactory extends KeyManagerFactorySpi {

    /**
     * Stores the key managers.
     */
    private final List<KeyManager> keyManagers = new ArrayList<>();
    
    private static final Logger LOGGER = Logger.getLogger(OCIKeyManagerFactory.class.getName());

    /**
     * Engine init.
     *
     * @param keystore the keystore
     * @param password the password
     */
    @Override
    protected void engineInit(KeyStore keystore, char[] password) {
    	LOGGER.log(INFO, "OCIKeyManagerFactory engineInit is invoked with keystore");
        OCIKeyManager manager = new OCIKeyManager(keystore, password);
        keyManagers.add(manager);
    }

    /**
     * Engine init.
     *
     * @param spec the spec
     */
    @Override
    protected void engineInit(ManagerFactoryParameters spec) {
    	LOGGER.log(INFO, "OCIKeyManagerFactory engineInit is invoked with ManagerFactoryParameters");
    }

    /**
     * Get key managers.
     *
     * @return keyManagers the key keyManagers
     */
    @Override
    protected KeyManager[] engineGetKeyManagers() {
    	LOGGER.log(INFO, "OCIKeyManagerFactory engineGetKeyManagers is invoked");
        return keyManagers.toArray(new KeyManager[0]);
    }
}