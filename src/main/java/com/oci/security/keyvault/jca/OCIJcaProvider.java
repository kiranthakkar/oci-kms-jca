package com.oci.security.keyvault.jca;

import java.lang.reflect.InvocationTargetException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Arrays;
import java.util.Collections;
import java.util.stream.Stream;
import java.util.logging.Logger;
import static java.util.logging.Level.INFO;

import com.oci.security.keyvault.jca.implementation.signature.AbstractKeyVaultKeylessSignature;
import com.oci.security.keyvault.jca.implementation.signature.KeyVaultKeylessEcSha256Signature;
import com.oci.security.keyvault.jca.implementation.signature.KeyVaultKeylessEcSha384Signature;
import com.oci.security.keyvault.jca.implementation.signature.KeyVaultKeylessEcSha512Signature;
import com.oci.security.keyvault.jca.implementation.signature.KeyVaultKeylessRsa256Signature;
import com.oci.security.keyvault.jca.implementation.signature.KeyVaultKeylessRsa512Signature;

/**
 * The OCI Key Vault security provider.
 *
 * @see Provider
 */
public final class OCIJcaProvider extends Provider {

    /**
     * Stores the name.
     */
    public static final String PROVIDER_NAME = OCIKeyStore.KEY_STORE_TYPE;

    /**
     * Stores the serial version UID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Stores the information.
     */
    private static final String INFORMATION= "OCI Key Vault JCA Provider";

    /**
     * Stores the version.
     */
    private static final Double VERSION = 1.0;
    
    private static final Logger LOGGER = Logger.getLogger(OCIJcaProvider.class.getName());

    /**
     * Constructor.
     */
    public OCIJcaProvider() {
    	super(PROVIDER_NAME, VERSION, INFORMATION); 
    	LOGGER.log(INFO, "OCIJCAProvider constructor is invoked");
        initialize();
        LOGGER.log(INFO, "OCIJCAProvider constructor is completed");
    }

    private void initialize() {
    	LOGGER.log(INFO, "OCIJCAProvider initialize is invoked");
        java.security.AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            putService(
                new Provider.Service(
                    this,
                    "KeyManagerFactory",
                    "SunX509",
                    OCIKeyManagerFactory.class.getName(),
                    Arrays.asList("SunX509", "IbmX509"),
                    null
                )
            );

            putService(
                new Provider.Service(
                    this,
                    "KeyStore",
                    OCIKeyStore.ALGORITHM_NAME,
                    OCIKeyStore.class.getName(),
                    Collections.singletonList(OCIKeyStore.ALGORITHM_NAME),
                    null
                )
            );
            Stream.of(
                KeyVaultKeylessRsa256Signature.class,
                KeyVaultKeylessRsa512Signature.class,
                KeyVaultKeylessEcSha256Signature.class,
                KeyVaultKeylessEcSha384Signature.class,
                KeyVaultKeylessEcSha512Signature.class)
                .forEach(c -> putService(
                    new Service(
                        this,
                        "Signature",
                        getAlgorithmName(c),
                        c.getName(),
                        null,
                        null
                    )
                ));
            LOGGER.log(INFO, "OCIJCAProvider initialize is complete");
            return null;
        });
    }


    private String getAlgorithmName(Class<? extends AbstractKeyVaultKeylessSignature> c) {
        try {
            return c.getDeclaredConstructor().newInstance().getAlgorithmName();
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            return "";
        }
    }
}