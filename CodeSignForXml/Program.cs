// -----------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// This code is provided AS IS without warranty of any kind. 
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace CodeSignForXml
{
    internal class Program
    {
        private const string XmlDsigMoreRsaHa256Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        private const string XmlEncSha256Url = "http://www.w3.org/2001/04/xmlenc#sha256";

        private static void Main(string[] args)
        {
            string signingMethod;
            string inputFile;
            string xmlString;
            string signedXml;
            X509Certificate2 privateCert = null;
            X509Certificate2 publicCert = null;
            bool pfxKey;

            if (args.Length < 4)
            {
                Console.WriteLine(
                    "Pfx Usage: SignXml.exe PFX {signMethod} {cert.pfx} {publicCert.cer} {signable xml} {signMethod}: SHA1 | SHA256 | SHA384 | SHA512");
                Console.WriteLine(
                    "Token Usage: SignXml.exe TOKEN {signMethod} {publicCert.cer} {signable xml} {signMethod}: SHA1 | SHA256 | SHA384 | SHA512");
                return;
            }

            if (args[0] == "PFX")
            {
                Console.Write("Input password:");
                string pswd = Console.ReadLine().Trim();

                signingMethod = args[1];

                privateCert = new X509Certificate2(args[2], pswd, X509KeyStorageFlags.Exportable);
                publicCert = new X509Certificate2(args[3]);

                inputFile = Path.GetFullPath(args[4]);
                xmlString = File.ReadAllText(inputFile);

                pfxKey = true;
            }
            else
            {
                signingMethod = args[1];

                publicCert = new X509Certificate2(args[2]);

                inputFile = Path.GetFullPath(args[3]);
                xmlString = File.ReadAllText(inputFile);

                var myStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                myStore.Open(OpenFlags.ReadOnly);

                foreach (X509Certificate2 cert in myStore.Certificates)
                {
                    if (cert.GetCertHashString() == publicCert.GetCertHashString())
                    {
                        privateCert = cert;
                        break;
                    }
                }

                pfxKey = false;
            }

            XmlDsigUtils.RegisterCryptoAlgorithms();

            if (StringComparer.InvariantCultureIgnoreCase.Compare(signingMethod, "SHA1") != 0)
            {
                XmlDsigSigningConfig config = XmlDsigUtils.GetSigningConfig(signingMethod);
                if (config == null)
                {
                    Console.WriteLine(
                        "SignMethod {0} is not supported. supported methods are SHA1 | SHA256 | SHA384 | SHA512",
                        signingMethod);
                    return;
                }

                signedXml = SignSHA256(pfxKey, xmlString, privateCert, publicCert, config);
            }
            else
            {
                signedXml = Sign(xmlString, privateCert, publicCert);
            }

            string outputFile = Path.Combine(Path.GetDirectoryName(inputFile),
                signingMethod + "Signed" + Path.GetFileName(inputFile));

            File.WriteAllText(outputFile, signedXml);

            Console.WriteLine("Signed xml being written to {0}", outputFile);
        }


        /// <summary>
        ///     Sign an XML blob and retrun the signed xml blob with signature.
        /// </summary>
        /// <param name="xmlString"></param>
        /// <param name="privateCert"></param>
        /// <param name="publicCert"></param>
        /// <returns></returns>
        public static string SignSHA256(bool pfxKey, string xmlString, X509Certificate2 privateCert,
            X509Certificate publicCert, XmlDsigSigningConfig config)
        {
            // Load an XML file into the XmlDocument object.
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            using (var reader = new StringReader(xmlString))
            {
                using (var xmlReader = new XmlTextReader(reader))
                {
                    xmlReader.DtdProcessing = DtdProcessing.Prohibit;
                    xmlDoc.Load(xmlReader);
                }
            }

            RSACryptoServiceProvider key;
            if (pfxKey)
            {
                var cspParams = new CspParameters(24);
                cspParams.KeyContainerName = "XML_DISG_RSA_KEY";
                key = new RSACryptoServiceProvider(cspParams);
                key.FromXmlString(privateCert.PrivateKey.ToXmlString(true));
            }
            else
            {
                key = (RSACryptoServiceProvider) privateCert.PrivateKey;
            }

            // Create a SignedXml object.
            var signedXml = new SignedXml(xmlDoc);

            // Add the key to the SignedXml document.
            signedXml.SigningKey = key;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = config.SignatureMethod;

            // Create a reference to be signed.
            var reference = new Reference();
            reference.Uri = "";
            reference.DigestMethod = config.DigestMethod;

            // Add an enveloped transformation to the reference.
            var env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Create a new KeyInfo object.
            var keyInfo = new KeyInfo();

            // Load the certificate into a KeyInfoX509Data object and add it to the KeyInfo object.
            keyInfo.AddClause(new KeyInfoX509Data(publicCert));

            // Add the KeyInfo object to the SignedXml object.
            signedXml.KeyInfo = keyInfo;

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));

            var sb = new StringBuilder();

            using (XmlWriter xmlwr = XmlWriter.Create(sb))
            {
                xmlDoc.WriteTo(xmlwr);
            }

            return sb.ToString();
        }

        /// <summary>
        ///     Sign an XML blob and retrun the signed xml blob with signature.
        /// </summary>
        /// <param name="xmlString"></param>
        /// <param name="privateCert"></param>
        /// <param name="publicCert"></param>
        /// <returns></returns>
        public static string Sign(string xmlString, X509Certificate2 privateCert, X509Certificate publicCert)
        {
            // Load an XML file into the XmlDocument object.
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            using (var reader = new StringReader(xmlString))
            {
                using (var xmlReader = new XmlTextReader(reader))
                {
                    xmlReader.DtdProcessing = DtdProcessing.Prohibit;
                    xmlDoc.Load(xmlReader);
                }
            }

            // Prepare the signing key
            var Key = (RSACryptoServiceProvider) privateCert.PrivateKey;

            // Create a SignedXml object.
            var signedXml = new SignedXml(xmlDoc);

            // Add the key to the SignedXml document.
            signedXml.SigningKey = Key;

            // Create a reference to be signed.
            var reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            var env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Create a new KeyInfo object.
            var keyInfo = new KeyInfo();

            // Load the certificate into a KeyInfoX509Data object and add it to the KeyInfo object.
            keyInfo.AddClause(new KeyInfoX509Data(publicCert));

            // Add the KeyInfo object to the SignedXml object.
            signedXml.KeyInfo = keyInfo;

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));

            var sb = new StringBuilder();

            using (XmlWriter xmlwr = XmlWriter.Create(sb))
            {
                xmlDoc.WriteTo(xmlwr);
            }

            return sb.ToString();
        }
    }
}