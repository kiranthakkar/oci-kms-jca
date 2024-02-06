package com.oci.security.keyvault.jca;

import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.SEVERE;

/**
 * The OCI Key Vault variant of the X509ExtendedKeyManager.
 *
 * @see X509ExtendedKeyManager
 */
public final class OCIKeyManager extends X509ExtendedKeyManager {

    /**
     * Stores the keystore.
     */
    private final KeyStore keystore;

    /**
     * Stores the password.
     */
    private final char[] password;
    
    private static final Logger LOGGER = Logger.getLogger(OCIKeyManager.class.getName());

    /**
     * Constructor.
     *
     * @param keystore the keystore
     * @param password the password
     */
    public OCIKeyManager(KeyStore keystore, char[] password) {
    	LOGGER.log(INFO, "OCIKeyManager constructor is invoked");
        this.keystore = keystore;
        if (password != null) {
            this.password = new char[password.length];
            System.arraycopy(password, 0, this.password, 0, password.length);
        } else {
            this.password = null;
        }
        LOGGER.log(INFO, "OCIKeyManager constructor is done");
    }

    /**
     * Choose client alias.
     *
     * @param keyType the keyType
     * @param issuers the issuers
     * @param socket the socket
     * @return alias the client alias
     */
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    	LOGGER.log(INFO, "OCIKeyManager chooseClientAlias is invoked");
        String alias = null;
        try {
            if (!keystore.getProvider().getName().equals(OCIJcaProvider.PROVIDER_NAME)
                && keystore.size() == 1) {
                	alias = keystore.aliases().nextElement();
            }
        } catch (KeyStoreException kse) {
        	LOGGER.log(SEVERE, "OCIKeyManager chooseClientAlias The exception is: {0}", kse.getMessage());
        }
        LOGGER.log(INFO, "OCIKeyManager chooseClientAlias is complete");
        return alias;
    }

    /**
     * Choose server alias.
     *
     * @param keyType the keyType
     * @param issuers the issuers
     * @param socket the socket
     * @return alias the server alias
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    	LOGGER.log(INFO, "OCIKeyManager chooseServerAlias is invoked");
        String alias = null;
        try {
            if (!keystore.getProvider().getName().equals(OCIJcaProvider.PROVIDER_NAME)
                && keystore.size() == 1) {
                	alias = keystore.aliases().nextElement();
            }
        } catch (KeyStoreException kse) {
        	LOGGER.log(SEVERE, "OCIKeyManager chooseServerAlias The exception is: {0}", kse.getMessage());
        }
        LOGGER.log(INFO, "OCIKeyManager chooseServerAlias is complete");
        return alias;
    }

    /**
     * Get client alias.
     *
     * @param keyType the keyType
     * @param issuers the issuers
     * @return alias the client alias
     */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
    	LOGGER.log(INFO, "OCIKeyManager getClientAliases is invoked");
        String[] aliases = null;
        try {
            aliases = Collections.list(keystore.aliases()).toArray(new String[0]);
        } catch (KeyStoreException kse) {
        	LOGGER.log(SEVERE, "OCIKeyManager getClientAliases The exception is: {0}", kse.getMessage());
        }
        LOGGER.log(INFO, "OCIKeyManager getClientAliases is completed");
        return aliases;
    }

    /**
     * Get certificate chain.
     *
     * @param alias the alias
     * @return chain the certificate chain
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
    	LOGGER.log(INFO, "OCIKeyManager getCertificateChain is invoked for alias: {0}",alias);
        List<X509Certificate> chain = new ArrayList<>();
        try {
            Certificate[] keystoreChain = keystore.getCertificateChain(alias);
            if (keystoreChain.length > 0) {
                for (Certificate certificate : keystoreChain) {
                    if (certificate instanceof X509Certificate) {
                        chain.add((X509Certificate) certificate);
                    }
                }
            } else {
            	LOGGER.log(INFO,"No certificate chain found for alias: {0}",alias);
            }
        } catch (KeyStoreException kse) {
        	LOGGER.log(SEVERE, "OCIKeyManager getCertificateChain The Exception is: {0}", kse.getMessage());
        }
        LOGGER.log(INFO, "OCIKeyManager getCertificateChain is completed for alias: {0}",alias);
        return chain.toArray(new X509Certificate[0]);
    }

    /**
     * Get private key.
     *
     * @param alias the alias
     * @return privateKey the private key
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
    	LOGGER.log(INFO, "OCIKeyManager getPrivateKey is invoked for alias: {0}",alias);
        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey) keystore.getKey(alias, password);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
        	LOGGER.log(SEVERE, "OCIKeyManager getPrivateKey The exception is: {0}",ex.getMessage());
        }
        LOGGER.log(INFO, "OCIKeyManager getPrivateKey is completed for alias: {0}",alias);
        return privateKey;
    }

    /**
     * Get server alias.
     *
     * @param keyType the keyType
     * @param issuers the issuers
     * @return alias the server alias
     */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
    	LOGGER.log(INFO, "OCIKeyManager getServerAliases is invoked");
        String[] serverAliases = new String[0];
        try {
            serverAliases = Collections.list(keystore.aliases()).toArray(new String[0]);
        } catch (KeyStoreException kse) {
        	LOGGER.log(SEVERE, "OCIKeyManager getServerAliases The Exception is: {0}", kse.getMessage());
        }
        LOGGER.log(INFO, "OCIKeyManager getServerAliases is completed");
        return serverAliases;
    }
}