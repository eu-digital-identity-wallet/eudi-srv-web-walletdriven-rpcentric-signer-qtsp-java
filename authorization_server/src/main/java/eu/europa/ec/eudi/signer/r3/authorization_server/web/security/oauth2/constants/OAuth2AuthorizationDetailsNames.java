package eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants;

public final class OAuth2AuthorizationDetailsNames {

	private OAuth2AuthorizationDetailsNames() {
	}

	public static final String TYPE = "type";
	public static final String CREDENTIAL_ID = "credentialID";
	public static final String SIGNATURE_QUALIFIER = "signatureQualifier";
	public static final String HASH_ALGORITHM_OID = "hashAlgorithmOID";
	public static final String DOCUMENT_DIGESTS = "documentDigests";
	public static final String HASH = "hash";

	// New fields for the updated credential scope (1.1.4)
	public static final String NUM_SIGNATURES = "numSignatures";
	public static final String HASH_TYPE = "hashType";
	public static final String SIGNED_PROPS = "signed_props";
	public static final String CIRCUMSTANTIAL_DATA = "circumstantialData";

	// New fields for credential-creation scope (1.1.2)
	public static final String ACR_VALUES = "acr_values";
	public static final String CREDENTIAL_CREATION_REQUEST = "credentialCreationRequest";

	// Type values
	public static final String TYPE_CREDENTIAL = "credential";
	public static final String TYPE_CREDENTIAL_CREATION = "credential_creation";
	public static final String TYPE_CREDENTIAL_DELETE = "credential_delete";
}
