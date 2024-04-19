package com.oci.security.keyvault.jca.implementation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.SEVERE;
import java.util.logging.Logger;

import com.oracle.bmc.ConfigFileReader;
import com.oracle.bmc.auth.AbstractAuthenticationDetailsProvider;
import com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider;
import com.oracle.bmc.auth.InstancePrincipalsAuthenticationDetailsProvider;
import com.oracle.bmc.certificates.CertificatesClient;
import com.oracle.bmc.certificates.requests.GetCertificateAuthorityBundleRequest;
import com.oracle.bmc.certificates.responses.GetCertificateAuthorityBundleResponse;
import com.oracle.bmc.certificatesmanagement.CertificatesManagementClient;
import com.oracle.bmc.certificatesmanagement.requests.GetCertificateAuthorityRequest;
import com.oracle.bmc.certificatesmanagement.responses.GetCertificateAuthorityResponse;
import com.oracle.bmc.http.client.jersey3.Jersey3HttpProvider;
import com.oracle.bmc.keymanagement.KmsCryptoClient;
import com.oracle.bmc.keymanagement.KmsManagementClient;
import com.oracle.bmc.keymanagement.model.SignDataDetails;
import com.oracle.bmc.keymanagement.model.SignDataDetails.MessageType;
import com.oracle.bmc.keymanagement.model.SignDataDetails.SigningAlgorithm;
import com.oracle.bmc.keymanagement.requests.GetKeyRequest;
import com.oracle.bmc.keymanagement.requests.SignRequest;
import com.oracle.bmc.keymanagement.responses.GetKeyResponse;
import com.oracle.bmc.keymanagement.responses.SignResponse;

/**
 * The OCI client for the OCI Key Vault.
 */
public class OCIKeyVaultClient {
	
	private String certificateAuthorityId;
	private String cryptoEndpoint;
	private String managementEndpoint;
	private String region;
	private AbstractAuthenticationDetailsProvider provider;

	private static final Logger LOGGER = Logger.getLogger(OCIKeyVaultClient.class.getName());

	private void initialize(String certificateAuthorityId, String cryptoEndpoint) {
		LOGGER.log(INFO, "OCIKeyVaultClient: initialize: method is invoked {0} {1}",
				new Object[] { certificateAuthorityId, cryptoEndpoint });
		this.certificateAuthorityId = certificateAuthorityId;
		this.cryptoEndpoint = cryptoEndpoint;
		this.managementEndpoint = this.cryptoEndpoint.replace("crypto", "management");
		this.region = this.cryptoEndpoint.substring(this.cryptoEndpoint.indexOf("kms.") + 4,
				this.cryptoEndpoint.indexOf(".oracle"));

		String ociAuthType = System.getProperty("oci.authType");
		LOGGER.log(INFO, "OCIKeyVaultClient: initialize: OCI Authentication type is: {0}", ociAuthType);
		if (ociAuthType != null && !ociAuthType.isEmpty() && ociAuthType.equalsIgnoreCase("instance_principal")) {
			this.provider = InstancePrincipalsAuthenticationDetailsProvider.builder().build();
			return;
		}
		ConfigFileReader.ConfigFile configFile;
		try {
			configFile = ConfigFileReader.parseDefault();
			this.provider = new ConfigFileAuthenticationDetailsProvider(configFile);
		} catch (IOException ioe) {
			LOGGER.log(SEVERE, "OCI KeyVault client initialization failed {0}", ioe.getMessage());
		}
		LOGGER.log(INFO, "OCIKeyVaultClient: initialize: method is complete");
	}

	public OCIKeyVaultClient() {
		LOGGER.log(INFO, "OCIKeyVaultClient: Constructor is invoked");
		this.initialize(System.getProperty("oci.certAuthorityId"), System.getProperty("oci.cryptoEndpoint"));
	}

	public OCIKeyVaultClient(String certificateAuthorityId, String cryptoEndpoint) {
		LOGGER.log(INFO, "OCIKeyVaultClient: Constructor with Arguments is invoked");
		this.initialize(certificateAuthorityId, cryptoEndpoint);
	}

	public static OCIKeyVaultClient createKeyVaultClientBySystemProperty() {
		LOGGER.log(INFO, "OCIKeyVaultClient: createKeyVaultClientBySystemProperty is invoked");
		String certificateAuthorityId = System.getProperty("oci.certAuthorityId");
		String cryptoEndpoint = System.getProperty("oci.cryptoEndpoint");
		return new OCIKeyVaultClient(certificateAuthorityId, cryptoEndpoint);
	}

	/**
	 * Get the list of aliases.
	 *
	 * @return the list of aliases.
	 */
	public List<String> getAliases() {
		LOGGER.log(INFO, "OCIKeyVaultClient: getAliases: is invoked");
		ArrayList<String> result = new ArrayList<>();
		GetCertificateAuthorityRequest certAuthReq = GetCertificateAuthorityRequest.builder()
				.certificateAuthorityId(this.certificateAuthorityId).opcRequestId("CertAuthorityAliases").build();
		CertificatesManagementClient cmc = CertificatesManagementClient.builder().region(this.region)
				.httpProvider(new Jersey3HttpProvider()).build(provider);
		GetCertificateAuthorityResponse certAuthRes = cmc.getCertificateAuthority(certAuthReq);
		if (certAuthRes != null && certAuthRes.get__httpStatusCode__() == 200) {
			result.add(certAuthRes.getCertificateAuthority().getName());
		}
		cmc.close();
		LOGGER.log(INFO, "OCIKeyVaultClient: getAliases: is complete {0}", result);
		return result;
	}

	/**
	 * Get the certificate.
	 *
	 * @param alias the alias.
	 * @return the certificate, or null if not found.
	 */
	public Certificate getCertificate(String alias) {
		LOGGER.log(INFO, "OCIKeyVaultClient: getCertificate: Get Certificate method is invoked for the alias {0}",
				alias);
		X509Certificate certificate = null;
		GetCertificateAuthorityBundleRequest certAuthBReq = GetCertificateAuthorityBundleRequest.builder()
				.certificateAuthorityId(certificateAuthorityId).opcRequestId("GetCertAuthorityBundle").build();
		CertificatesClient cc = CertificatesClient.builder().region(this.region).httpProvider(new Jersey3HttpProvider())
				.build(provider);
		GetCertificateAuthorityBundleResponse certAuthBRes = cc.getCertificateAuthorityBundle(certAuthBReq);
		if (certAuthBRes != null && certAuthBRes.get__httpStatusCode__() == 200) {
			String certificateString = certAuthBRes.getCertificateAuthorityBundle().getCertificatePem();
			if (certificateString != null) {
				certificateString = certificateString.replace("-----BEGIN CERTIFICATE-----", "")
						.replace("-----END CERTIFICATE-----", "").replace("\n", "");
				try {
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					certificate = (X509Certificate) cf.generateCertificate(
							new ByteArrayInputStream(Base64.getDecoder().decode(certificateString)));
				} catch (CertificateException ce) {
					LOGGER.log(SEVERE, "OCIKeyVaultClient getCertificate is invalid {0}", ce.getMessage());
				}
			}
		}
		LOGGER.log(INFO, "OCIKeyVaultClient: getCertificate: Get Certificate method is finished for the alias {0}",
				alias);
		cc.close();
		return certificate;
	}

	/**
	 * Get the key
	 * 
	 * @param alias    the alias.
	 * @param password the password.
	 * @return the key.
	 */
	public Key getKey(String alias, char[] password) {
		LOGGER.log(INFO, "OCIKeyVaultClient: getKey: get Key method is invoked for the alias {0}", alias);
		GetCertificateAuthorityRequest certAuthReq = GetCertificateAuthorityRequest.builder()
				.certificateAuthorityId(this.certificateAuthorityId).opcRequestId("CertAuthorityAliases").build();
		CertificatesManagementClient cmc = CertificatesManagementClient.builder().region(this.region)
				.httpProvider(new Jersey3HttpProvider()).build(provider);
		GetCertificateAuthorityResponse certAuthRes = cmc.getCertificateAuthority(certAuthReq);
		String kmsKeyID = null;
		if (certAuthRes != null && certAuthRes.get__httpStatusCode__() == 200) {
			kmsKeyID = certAuthRes.getCertificateAuthority().getKmsKeyId();
		}

		if (kmsKeyID != null) {
			GetKeyRequest getKReq = GetKeyRequest.builder().keyId(kmsKeyID).opcRequestId("GetKeyForCert").build();
			KmsManagementClient kmsManagementClient = KmsManagementClient.builder().endpoint(managementEndpoint)
					.httpProvider(new Jersey3HttpProvider()).build(provider);
			GetKeyResponse getKRes = kmsManagementClient.getKey(getKReq);
			if (getKRes != null && getKRes.get__httpStatusCode__() == 200) {
				com.oracle.bmc.keymanagement.model.Key ociKey = getKRes.getKey();
				String alg = ociKey.getKeyShape().getAlgorithm().getValue();
				int length = ociKey.getKeyShape().getLength();
				String keyId = ociKey.getId();
				String keyName = ociKey.getDisplayName();
				LOGGER.log(INFO, "OCIKeyVaultClient: getKey: get Key method is complete for the alias {0}", alias);
				kmsManagementClient.close();
				cmc.close();
				return new OCIPrivateKey(alg, keyId, keyName, length, this);
			}
			kmsManagementClient.close();
		}
		cmc.close();
		LOGGER.log(SEVERE, "OCIKeyVaultClient: getKey: get Key method is returning NULL for the alias {0}", alias);
		return null;

	}

	/**
	 * Get the key
	 * 
	 * @param keyId    The keyId of the private key.
	 * @return the key.
	 */
	public Key getPrivateKey(String keyId) {
		LOGGER.log(INFO, "OCIKeyVaultClient: getPrivateKey: get Key method is invoked for the key {0}", keyId);
		GetKeyRequest getKReq = GetKeyRequest.builder().keyId(keyId).opcRequestId("GetKeyForCert").build();
		KmsManagementClient kmsManagementClient = KmsManagementClient.builder().endpoint(managementEndpoint)
				.httpProvider(new Jersey3HttpProvider()).build(provider);
		GetKeyResponse getKRes = kmsManagementClient.getKey(getKReq);
		if (getKRes != null && getKRes.get__httpStatusCode__() == 200) {
			com.oracle.bmc.keymanagement.model.Key ociKey = getKRes.getKey();
			String alg = ociKey.getKeyShape().getAlgorithm().getValue();
			int length = ociKey.getKeyShape().getLength();
			String keyName = ociKey.getDisplayName();
			kmsManagementClient.close();
			LOGGER.log(INFO, "OCIKeyVaultClient: getKey: get Key method is complete for the key {0}", keyId);
			return new OCIPrivateKey(alg, keyId, keyName, length, this);
		}
		kmsManagementClient.close();
		LOGGER.log(SEVERE, "OCIKeyVaultClient: getKey: get Key method is returning NULL for the key {0}", keyId);
		return null;

	}

	/**
	 * get signature by key vault
	 * 
	 * @param digestName  digestName
	 * @param digestValue digestValue
	 * @param signAlgorithm signAlgorithm
	 * @param keyId       The key id
	 * @return signature
	 */
	public byte[] getSignedWithPrivateKey(String digestName, String digestValue, SigningAlgorithm signAlgorithm,
			String keyId) {
		LOGGER.log(INFO, "OCIKeyVaultClient: getSigned: is invoked with arguments: {0} {1} {2} {3}",
				new Object[] { digestName, digestValue, signAlgorithm.getValue(), keyId });

		// Get the key version for the selected key
		GetKeyRequest keyReq = GetKeyRequest.builder().keyId(keyId).build();
		KmsManagementClient kmsManagementClient = KmsManagementClient.builder().endpoint(managementEndpoint)
				.httpProvider(new Jersey3HttpProvider()).build(provider);
		GetKeyResponse keyRes = kmsManagementClient.getKey(keyReq);
		if (keyRes != null && keyRes.get__httpStatusCode__() == 200) {
			String keyVersionID = keyRes.getKey().getCurrentKeyVersion();

			// Now create Sign Request object and get it signed from OCI vault
			SignDataDetails signDataDetails = SignDataDetails.builder().keyId(keyId).keyVersionId(keyVersionID)
					.messageType(MessageType.Digest).signingAlgorithm(signAlgorithm)
					.message(digestValue).build();
			SignRequest signRequest = SignRequest.builder().signDataDetails(signDataDetails).build();
			KmsCryptoClient kmsCryptoClient = KmsCryptoClient.builder().endpoint(this.cryptoEndpoint)
					.httpProvider(new Jersey3HttpProvider()).build(provider);
			SignResponse signResponse = kmsCryptoClient.sign(signRequest);
			if (signResponse != null && signResponse.get__httpStatusCode__() == 200) {
				kmsManagementClient.close();
				kmsCryptoClient.close();
				LOGGER.log(INFO, "OCIKeyVaultClient: getSigned: is returning with signature");
				return Base64.getDecoder().decode(signResponse.getSignedData().getSignature().getBytes());
			}
			kmsCryptoClient.close();
		}
		kmsManagementClient.close();
		LOGGER.log(SEVERE, "OCIKeyVaultClient: getSigned: is returning NULL");
		return new byte[0];
	}
}