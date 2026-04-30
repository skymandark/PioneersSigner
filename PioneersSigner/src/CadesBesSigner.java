import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import safenet.jcprov.CK_ATTRIBUTE;
import safenet.jcprov.CK_C_INITIALIZE_ARGS;
import safenet.jcprov.CK_MECHANISM;
import safenet.jcprov.CK_OBJECT_HANDLE;
import safenet.jcprov.CK_SESSION_HANDLE;
import safenet.jcprov.CryptokiEx;
import safenet.jcprov.LongRef;
import safenet.jcprov.constants.CKA;
import safenet.jcprov.constants.CKM;
import safenet.jcprov.constants.CKO;
import safenet.jcprov.constants.CKU;

public class CadesBesSigner {

    /**
     * Sign data and return CAdES-BES signature compliant with ITIDA specifications
     */
    public byte[] sign(String sData) throws Exception {
        // Initialize HSM handler
        AHSMHandeler h = new AHSMHandeler();
        CK_SESSION_HANDLE session = h.session();
        CK_OBJECT_HANDLE privateKey = h.privateKey();
        X509Certificate certificate = h.certificate();

        // Add BouncyCastle provider
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Prepare content (raw data)
        byte[] dataBytes = sData.getBytes(StandardCharsets.UTF_8);

        // Create ContentSigner using HSM (using SHA256_RSA_PKCS)
        ContentSigner signer = new ATaxContentSigner(session, privateKey);

        // Build signed attributes (CAdES-BES) - ITIDA compliant
        AttributeTable cadesAttrs = buildCAdESAttributes(dataBytes, certificate);

        // Build SignerInfo
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BC").build();

        DefaultSignedAttributeTableGenerator attrGen = new DefaultSignedAttributeTableGenerator(cadesAttrs);

        JcaSignerInfoGeneratorBuilder sigInfoBuilder = new JcaSignerInfoGeneratorBuilder(dcp)
                .setSignedAttributeGenerator(attrGen);

        SignerInfoGenerator sigInfo = sigInfoBuilder.build(signer, new X509CertificateHolder(certificate.getEncoded()));

        // Generate detached CMS (CAdES-BES) with digestedData content type
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(sigInfo);
        gen.addCertificates(new JcaCertStore(Collections.singletonList(certificate)));

        // Create detached signature with DigestData content type (ITIDA requires digestedData)
        CMSTypedData content = new CMSProcessableByteArray(PKCSObjectIdentifiers.digestedData, dataBytes);
        CMSSignedData signedData = gen.generate(content, false); // false = detached signature

        // Close HSM connection
        h.endConnection();

        byte[] sig = signedData.getEncoded();

        // Verify signature structure according to ITIDA specs
        verifySignatureStructure(sig);

        // Verify signature with original data
        boolean verified = verify(dataBytes, sig);
        System.out.println("Signature verification: " + (verified ? "Success" : "Failed"));

        if (!verified) {
            throw new Exception("Signature verification failed - message digest mismatch");
        }

        return sig;
    }

    /**
     * Build CAdES-BES signed attributes according to ITIDA specification
     * NOTE: Do NOT add messageDigest manually here. BouncyCastle will auto-add it.
     */
    private AttributeTable buildCAdESAttributes(byte[] content, X509Certificate certificate) throws Exception {
        System.out.println("\n=== Building CAdES-BES Attributes (ITIDA Compliant) ===");

        // For logging only: compute digest (do not insert manually)
        byte[] contentDigest = MessageDigest.getInstance("SHA-256").digest(content);
        System.out.println("MessageDigest (SHA-256) - computed for logging only: " + Base64.getEncoder().encodeToString(contentDigest));

        // ESSCertIDv2 (SHA-256 hash of certificate)
        byte[] certEncoded = certificate.getEncoded();
        byte[] certHash = MessageDigest.getInstance("SHA-256").digest(certEncoded);
        System.out.println("Certificate Hash (SHA-256): " + Base64.getEncoder().encodeToString(certHash));

        AlgorithmIdentifier hashAlg = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        ESSCertIDv2 essCertID = new ESSCertIDv2(hashAlg, certHash);
        SigningCertificateV2 signingCertV2 = new SigningCertificateV2(new ESSCertIDv2[]{essCertID});

        ASN1EncodableVector attrVector = new ASN1EncodableVector();

        // 1) ContentType = digestedData (1.2.840.113549.1.7.5)
        attrVector.add(new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.digestedData)));
        System.out.println("✓ ContentType Attribute added (digestedData)");

        // 2) ESSSigningCertificateV2
        attrVector.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(signingCertV2)));
        System.out.println("✓ ESSSigningCertificateV2 added");

        // 3) SigningTime (UTC time)
        Date signingTime = new Date();
        attrVector.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(signingTime))));
        System.out.println("✓ SigningTime: " + signingTime);

        System.out.println("=== Manual Attributes: 3 (messageDigest will be auto-added by BC) ===");
        System.out.println("=== Expected Total: 4 attributes as per ITIDA ===\n");

        return new AttributeTable(attrVector);
    }

    /**
     * Verify the signature structure matches ITIDA requirements
     */
    public void verifySignatureStructure(byte[] signature) throws Exception {
        System.out.println("\n=== Verifying Signature Structure (ITIDA Compliance) ===");

        try {
            CMSSignedData signedData = new CMSSignedData(signature);

            // 1. eContent should be null (detached)
            CMSTypedData signedContent = signedData.getSignedContent();
            if (signedContent != null) {
                System.err.println(" ERROR: eContent is present! Should be NULL for detached signature");
            } else {
                System.out.println("✓ eContent: NULL (Detached signature - Correct)");
            }

            // 2. ContentType OID
            ASN1ObjectIdentifier contentTypeOID = new ASN1ObjectIdentifier(signedData.getSignedContentTypeOID());
            System.out.println("✓ ContentType OID: " + contentTypeOID);
            if (PKCSObjectIdentifiers.digestedData.equals(contentTypeOID)) {
                System.out.println("✓ ContentType matches DigestData OID (1.2.840.113549.1.7.5) - Correct");
            } else {
                System.err.println(" WARNING: ContentType is " + contentTypeOID +
                        " but ITIDA expects DigestData (1.2.840.113549.1.7.5)");
            }

            // 3. SignerInfo count
            SignerInformationStore signers = signedData.getSignerInfos();
            System.out.println("✓ Number of SignerInfos: " + signers.size() + " (Expected: 1)");
            if (signers.size() != 1) {
                System.err.println(" ERROR: Expected exactly 1 SignerInfo, found " + signers.size());
            }

            // 4. Signed Attributes
            SignerInformation signer = signers.getSigners().iterator().next();
            AttributeTable signedAttrs = signer.getSignedAttributes();

            System.out.println("\n--- Signed Attributes (Must be 4 according to ITIDA) ---");

            if (signedAttrs != null) {
                System.out.println("Total Signed Attributes: " + signedAttrs.size());

                Attribute contentType = signedAttrs.get(CMSAttributes.contentType);
                Attribute messageDigest = signedAttrs.get(CMSAttributes.messageDigest);
                Attribute signingCert = signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
                Attribute signingTime = signedAttrs.get(CMSAttributes.signingTime);

                System.out.println("1. ContentType (1.2.840.113549.1.9.3): " +
                        (contentType != null ? "✓ Present" : " Missing"));
                if (contentType != null) {
                    ASN1ObjectIdentifier ctOID = (ASN1ObjectIdentifier) contentType.getAttrValues().getObjectAt(0);
                    System.out.println("   Value: " + ctOID);
                }

                System.out.println("2. MessageDigest (1.2.840.113549.1.9.4): " +
                        (messageDigest != null ? "✓ Present" : " Missing"));

                System.out.println("3. ESSSigningCertificateV2 (1.2.840.113549.1.9.16.2.47): " +
                        (signingCert != null ? "✓ Present" : " Missing"));

                System.out.println("4. SigningTime (1.2.840.113549.1.9.5): " +
                        (signingTime != null ? "✓ Present" : " Missing"));
            } else {
                System.err.println(" ERROR: No signed attributes found!");
            }

            // 5. Unsigned attributes must not be present
            AttributeTable unsignedAttrs = signer.getUnsignedAttributes();
            if (unsignedAttrs != null && unsignedAttrs.size() > 0) {
                System.err.println(" WARNING: Unsigned attributes found (" + unsignedAttrs.size() +
                        "). ITIDA specifies no unsigned attributes!");
            } else {
                System.out.println("✓ Unsigned Attributes: None (Correct)");
            }

            // 6. Digest algorithm
            String digestAlgOID = signer.getDigestAlgOID();
            System.out.println("✓ Digest Algorithm: " + digestAlgOID +
                    " (Expected: 2.16.840.1.101.3.4.2.1 for SHA-256)");

            // 7. Signature algorithm
            String encryptionAlgOID = signer.getEncryptionAlgOID();
            System.out.println("✓ Signature Algorithm: " + encryptionAlgOID +
                    " (Expected: 1.2.840.113549.1.1.11 for sha256WithRSAEncryption)");

            System.out.println("=== Structure Verification Complete ===\n");

        } catch (Exception e) {
            System.err.println("Error verifying signature structure: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Verify the signature with original data
     */
    private boolean verify(byte[] dataBytes, byte[] signature) throws Exception {
        try {
            System.out.println("\n=== Starting Signature Verification ===");

            CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(dataBytes), signature);

            if (signedData.getSignedContent() == null) {
                System.err.println(" ERROR: Expected detached signature but content is null");
                return false;
            }

            SignerInformationStore signers = signedData.getSignerInfos();
            if (signers.size() != 1) {
                System.err.println(" ERROR: Expected exactly one signer, found: " + signers.size());
                return false;
            }

            SignerInformation signer = signers.getSigners().iterator().next();

            AttributeTable signedAttrs = signer.getSignedAttributes();
            if (signedAttrs == null || signedAttrs.size() == 0) {
                System.err.println(" ERROR: No signed attributes found");
                return false;
            }

            Attribute messageDigestAttr = signedAttrs.get(CMSAttributes.messageDigest);
            if (messageDigestAttr == null) {
                System.err.println(" ERROR: No messageDigest attribute found");
                return false;
            }

            ASN1Set values = messageDigestAttr.getAttrValues();
            ASN1OctetString signedDigest = (ASN1OctetString) values.getObjectAt(0);
            byte[] signedDigestBytes = signedDigest.getOctets();

            byte[] actualDigest = MessageDigest.getInstance("SHA-256").digest(dataBytes);

            if (!Arrays.equals(signedDigestBytes, actualDigest)) {
                System.err.println(" Message digest mismatch!");
                System.err.println("Signed digest: " + Base64.getEncoder().encodeToString(signedDigestBytes));
                System.err.println("Actual digest: " + Base64.getEncoder().encodeToString(actualDigest));
                return false;
            } else {
                System.out.println("✓ Message digest matches successfully!");
            }

            Store<X509CertificateHolder> certStore = signedData.getCertificates();
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> certMatches =
                    certStore.getMatches((Selector<X509CertificateHolder>) signer.getSID());
            if (certMatches.isEmpty()) {
                System.err.println(" ERROR: No certificate found for signer");
                return false;
            }

            X509CertificateHolder certHolder = certMatches.iterator().next();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(certHolder.getEncoded())
            );

            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider("BC").build(cert);

            boolean signatureValid = signer.verify(verifier);
            System.out.println("✓ Signature cryptographic verification: " +
                    (signatureValid ? "SUCCESS" : "FAILED"));

            System.out.println("=== Verification Complete ===\n");
            return signatureValid;

        } catch (Exception e) {
            System.err.println(" Verification failed: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // pioneerssign يرجع signature فقط
    public String startSigning(String json) throws Exception {
        JsonSerializer serializer = new JsonSerializer(json);
        String canonical = serializer.toCanonicalStringFromSerializedDocument();

        System.out.println("Canonical String Length: " + canonical.length() + " characters");

        CadesBesSigner signer = new CadesBesSigner();
        byte[] signature = signer.sign(canonical);

        String signatureString = Base64.getEncoder().encodeToString(signature);

        // يرجع signature فقط
        return signatureString;
    }

    // invoicesswitch يرجع الفاتورة كاملة
    public String startInvoiceSigning(String json) throws Exception {
        System.out.println("=== Starting Invoice Signing Process ===");

        // Use the same JsonSerializer for invoices to get the same structure
        JsonSerializer serializer = new JsonSerializer(json);
        String canonical = serializer.toCanonicalStringFromSerializedDocument();

        System.out.println("Invoice Canonical String Length: " + canonical.length() + " characters");

        CadesBesSigner signer = new CadesBesSigner();
        byte[] signature = signer.sign(canonical);

        String signatureString = Base64.getEncoder().encodeToString(signature);

        // Use the same addSignature method to get identical structure
        String result = serializer.addSignature(signatureString);

        System.out.println("=== Invoice Signing Completed ===");
        return result;
    }

    // -----------------------------------------------------------------------
    // JsonSerializer: serializes document exactly as sent then canonicalizes
    // -----------------------------------------------------------------------
    public static class JsonSerializer {
        private final ObjectMapper mapper;
        private final ObjectNode originalDocumentNode;

        public JsonSerializer(String jsonInput) throws Exception {
            this.mapper = new ObjectMapper();
            // احتفظ بالقيمة الرقمية كما أرسلتها (BigDecimal) واطبعها بدون Scientific notation
            this.mapper.enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
            this.mapper.enable(SerializationFeature.WRITE_BIGDECIMAL_AS_PLAIN);
            JsonNode root = mapper.readTree(jsonInput);
            if (!root.isObject()) {
                throw new IllegalArgumentException("Root must be a JSON object representing the document");
            }
            this.originalDocumentNode = (ObjectNode) root;
        }

        /**
         * Serialize the document exactly as it will be sent (without signature),
         * then canonicalize that serialized string to produce the canonical string to be signed.
         */
        public String toCanonicalStringFromSerializedDocument() throws Exception {
            String serializedDoc = mapper.writeValueAsString(originalDocumentNode);
            return canonicalizeJsonString(serializedDoc);
        }

        /**
         * Add signature into a deep copy of original document and return final submission:
         * {"documents":[ document_with_signatures ]}
         */
        public String addSignature(String cades) {
            try {
                ObjectNode documentCopy = originalDocumentNode.deepCopy();

                ObjectNode signatureObject = mapper.createObjectNode();
                signatureObject.put("signatureType", "I");
                signatureObject.put("value", cades);

                ArrayNode signaturesArray = mapper.createArrayNode();
                signaturesArray.add(signatureObject);

                documentCopy.set("signatures", signaturesArray);

                ObjectNode submission = mapper.createObjectNode();
                ArrayNode docs = mapper.createArrayNode();
                docs.add(documentCopy);
                submission.set("documents", docs);

                return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(submission);
            } catch (Exception e) {
                throw new RuntimeException("Failed to add signature to document", e);
            }
        }

        // Canonicalize the serialized document string using a streaming parser
        private String canonicalizeJsonString(String json) throws Exception {
            JsonFactory factory = new JsonFactory();
            try (JsonParser p = factory.createParser(json)) {
                JsonToken t = p.nextToken();
                if (t != JsonToken.START_OBJECT) {
                    throw new IllegalArgumentException("Document must be a JSON object");
                }
                StringBuilder sb = new StringBuilder();
                processObject(p, sb);
                return sb.toString();
            }
        }

        private void processObject(JsonParser p, StringBuilder sb) throws IOException {
            while (true) {
                JsonToken t = p.nextToken();
                if (t == JsonToken.END_OBJECT) return;
                if (t != JsonToken.FIELD_NAME) throw new IOException("Expected FIELD_NAME but got: " + t);
                String name = p.currentName();
                String nameUpper = name.toUpperCase(Locale.ROOT);
                sb.append("\"").append(nameUpper).append("\"");
                JsonToken valTok = p.nextToken();
                processValue(p, valTok, sb, nameUpper);
            }
        }

        private void processValue(JsonParser p, JsonToken valTok, StringBuilder sb, String parentArrayName) throws IOException {
            if (valTok == JsonToken.START_OBJECT) {
                processObject(p, sb);
            } else if (valTok == JsonToken.START_ARRAY) {
                while (true) {
                    JsonToken t = p.nextToken();
                    if (t == JsonToken.END_ARRAY) return;
                    // prefix each element with array property name uppercase
                    sb.append("\"").append(parentArrayName).append("\"");
                    processValue(p, t, sb, parentArrayName);
                }
            } else if (valTok == JsonToken.VALUE_STRING) {
                sb.append("\"").append(p.getText()).append("\"");
            } else if (valTok == JsonToken.VALUE_NUMBER_INT || valTok == JsonToken.VALUE_NUMBER_FLOAT) {
                sb.append("\"").append(p.getText()).append("\"");
            } else if (valTok == JsonToken.VALUE_TRUE || valTok == JsonToken.VALUE_FALSE) {
                sb.append("\"").append(p.getText()).append("\"");
            } else if (valTok == JsonToken.VALUE_NULL) {
                sb.append("\"\"");
            } else {
                throw new IOException("Unsupported token type in canonicalization: " + valTok);
            }
        }
    }

    // -----------------------------------------------------------------------
    // AHSMHandeler: HSM connection and key/certificate management
    // -----------------------------------------------------------------------
    public static class AHSMHandeler {
        private CK_OBJECT_HANDLE privateKeyHandle = null;
        private final CK_SESSION_HANDLE sessionHandle = new CK_SESSION_HANDLE();
        private X509Certificate cert = null;

        public AHSMHandeler() {
            long slotId = 0L;
            String password = "Pioneers123";

            try {
                CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(2L));
                CryptokiEx.C_OpenSession(slotId, 2L, (Object)null, (Object)null, this.sessionHandle);
                if (password.length() > 0) {
                    CryptokiEx.C_Login(this.sessionHandle, CKU.USER, password.getBytes(StandardCharsets.US_ASCII), (long)password.length());
                }

                System.out.println("HSM Slot " + slotId + " connected successfully");
                this.getPrivateKey();
                this.getX509Certificate();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        private void getPrivateKey() {
            CK_ATTRIBUTE[] privateKeyTemplate = new CK_ATTRIBUTE[]{
                    new CK_ATTRIBUTE(CKA.CLASS, CKO.PRIVATE_KEY),
                    new CK_ATTRIBUTE(CKA.LABEL, "esealkey")
            };
            CryptokiEx.C_FindObjectsInit(this.sessionHandle, privateKeyTemplate, (long)privateKeyTemplate.length);
            CK_OBJECT_HANDLE[] found = new CK_OBJECT_HANDLE[]{new CK_OBJECT_HANDLE()};
            LongRef countRef = new LongRef();
            CryptokiEx.C_FindObjects(this.sessionHandle, found, (long)found.length, countRef);
            CryptokiEx.C_FindObjectsFinal(this.sessionHandle);
            this.privateKeyHandle = found[0];
            System.out.println("✓ Private key found");
        }

        private void getX509Certificate() throws CertificateException {
            CK_ATTRIBUTE[] privateKeyTemplate = new CK_ATTRIBUTE[]{
                    new CK_ATTRIBUTE(CKA.CLASS, CKO.CERTIFICATE),
                    new CK_ATTRIBUTE(CKA.LABEL, "esealkey")
            };
            CryptokiEx.C_FindObjectsInit(this.sessionHandle, privateKeyTemplate, (long)privateKeyTemplate.length);
            CK_OBJECT_HANDLE[] found = new CK_OBJECT_HANDLE[]{new CK_OBJECT_HANDLE()};
            LongRef countRef = new LongRef();
            CryptokiEx.C_FindObjects(this.sessionHandle, found, (long)found.length, countRef);
            CryptokiEx.C_FindObjectsFinal(this.sessionHandle);
            CK_OBJECT_HANDLE certHandle = found[0];
            CK_ATTRIBUTE[] certValueTemplate = new CK_ATTRIBUTE[]{new CK_ATTRIBUTE(CKA.VALUE, (Object)null)};
            CryptokiEx.C_GetAttributeValue(this.sessionHandle, certHandle, certValueTemplate, (long)certValueTemplate.length);
            long len = certValueTemplate[0].valueLen;
            if (len <= 0L) {
                throw new RuntimeException("Certificate value length is invalid: " + len);
            } else {
                certValueTemplate[0].pValue = new byte[(int)len];
                CryptokiEx.C_GetAttributeValue(this.sessionHandle, certHandle, certValueTemplate, (long)certValueTemplate.length);
                byte[] certBytes = (byte[])certValueTemplate[0].pValue;
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                this.cert = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
                // Use getSubjectX500Principal instead of deprecated getSubjectDN
                System.out.println("✓ Certificate loaded: " + this.cert.getSubjectX500Principal().getName());
            }
        }

        public X509Certificate certificate() {
            return this.cert;
        }

        public CK_OBJECT_HANDLE privateKey() {
            return this.privateKeyHandle;
        }

        public CK_SESSION_HANDLE session() {
            return this.sessionHandle;
        }

        public void endConnection() {
            try {
                CryptokiEx.C_Logout(this.sessionHandle);
            } catch (Exception ignored) {}
            try {
                CryptokiEx.C_CloseSession(this.sessionHandle);
            } catch (Exception ignored) {}
            try {
                CryptokiEx.C_Finalize((Object)null);
            } catch (Exception ignored) {}
            System.out.println("✓ HSM connection closed");
        }
    }

    // -----------------------------------------------------------------------
    // ATaxContentSigner: Custom ContentSigner using HSM
    // -----------------------------------------------------------------------
    public static class ATaxContentSigner implements ContentSigner {
        private static final ASN1ObjectIdentifier OID_SHA256WITHRSA = new ASN1ObjectIdentifier("1.2.840.113549.1.1.11");
        private final CK_SESSION_HANDLE session;
        private final CK_OBJECT_HANDLE privateKey;
        private final CK_MECHANISM mechanism;
        private final AlgorithmIdentifier algId;
        private final ByteArrayOutputStream buffer;

        public ATaxContentSigner(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privateKey) {
            this(session, privateKey, new CK_MECHANISM(CKM.SHA256_RSA_PKCS), new AlgorithmIdentifier(OID_SHA256WITHRSA, DERNull.INSTANCE));
        }

        public ATaxContentSigner(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privateKey, CK_MECHANISM mechanism, AlgorithmIdentifier algId) {
            this.buffer = new ByteArrayOutputStream();
            this.session = session;
            this.privateKey = privateKey;
            this.mechanism = mechanism;
            this.algId = algId;
        }

        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return this.algId;
        }

        public OutputStream getOutputStream() {
            this.buffer.reset();
            return this.buffer;
        }

        public byte[] getSignature() {
            try {
                byte[] tbs = this.buffer.toByteArray();
                CryptokiEx.C_SignInit(this.session, this.mechanism, this.privateKey);
                LongRef sigLen = new LongRef();
                CryptokiEx.C_Sign(this.session, tbs, (long)tbs.length, (byte[])null, sigLen);
                byte[] signature = new byte[(int)sigLen.value];
                CryptokiEx.C_Sign(this.session, tbs, (long)tbs.length, signature, sigLen);
                return signature;
            } catch (Exception e) {
                throw new RuntimeException("HSM signing failed via jcprov", e);
            }
        }
    }
}