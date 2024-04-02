package com.oci.security.keyvault.jca.implementation.signature;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import com.oci.security.keyvault.jca.implementation.OCIKeyVaultClient;
import com.oci.security.keyvault.jca.implementation.OCIPrivateKey;
import com.oracle.bmc.keymanagement.model.SignDataDetails.SigningAlgorithm;

/**
 * KeyVault Signature to keyless sign
 */
public abstract class AbstractKeyVaultKeylessSignature extends SignatureSpi {

    protected OCIKeyVaultClient keyVaultClient;

    // message digest implementation we use for hashing the data
    protected MessageDigest messageDigest;

    protected String keyId;

    /**
     * The default algorithm for certificate sign when the certificate is stored in Key Vault.
     * @return the default algorithm.
     */
    public abstract String getAlgorithmName();
    public abstract SigningAlgorithm getOCIAlgorithm();

    // After throw UnsupportedOperationException, other methods will be called.
    // such as RSAPSSSignature#engineInitVerify.
    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        throw new UnsupportedOperationException("engineInitVerify() not supported");
    }

    // After throw UnsupportedOperationException, other methods will be called.
    // such as RSAPSSSignature#engineVerify.
    @Override
    protected boolean engineVerify(byte[] signature) {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    // After throw UnsupportedOperationException, other methods will be called.
    // such as ECDSASignature#engineGetParameter.
    @Override
    @Deprecated
    protected Object engineGetParameter(String param)
        throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    // After throw UnsupportedOperationException, other methods will be called.
    // such as RSAPSSSignature#engineSetParameter.
    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    // After throw UnsupportedOperationException, other methods will be called.
    // such as RSAPSSSignature#engineInitSign.
    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) {
        if (privateKey instanceof OCIPrivateKey) {
            keyId = ((OCIPrivateKey) privateKey).getKid();
            keyVaultClient = ((OCIPrivateKey) privateKey).getKeyVaultClient();
        } else {
            throw new UnsupportedOperationException("engineInitSign() not supported which private key is not instance of OCIPrivateKey");
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) {
        engineInitSign(privateKey, null);
    }

    /**
     * Get the message digest value.
     * @return the message digest value.
     */
    protected byte[] getDigestValue() {
        return messageDigest.digest();
    }

    @Override
    protected void engineUpdate(byte b) {
        this.messageDigest.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        this.messageDigest.update(b, off, len);
    }

    @Override
    protected void engineUpdate(ByteBuffer b) {
        this.messageDigest.update(b);
    }

    //Override this method just do not throw an exception to enable this signature
    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
    }

    /**
     * Add this method to enable getParameters which added in this commit:
     * https://github.com/openjdk/jdk/commit/316140ff92af7ac1aadb74de9cd37a5f3c412406
     * You can find this logic in file SignatureScheme.java and line 202 in this commit.
     * Which will call this method. If we don't support this method, this algorithm won't be available
     * @return AlgorithmParameters
     */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

}