// -----------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// This code is provided AS IS without warranty of any kind. 
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;

namespace CodeSignForXml
{
    /// <summary>
    ///     Base class for SHA2 family Signature Description
    /// </summary>
    public class Sha2SignatureDescription : SignatureDescription
    {
        /// <summary>
        ///     Hash Algorithm
        /// </summary>
        private readonly string _algorithm;

        /// <summary>
        ///     Construct an SHA2ignatureDescription object. The default settings for this object
        ///     are:
        ///     <list type="bullet">
        ///         <item>Key algorithm - <see cref="RSACryptoServiceProvider" /></item>
        ///         <item>Formatter algorithm - <see cref="RSAPKCS1SignatureFormatter" /></item>
        ///         <item>Deformatter algorithm - <see cref="RSAPKCS1SignatureDeformatter" /></item>
        ///     </list>
        /// </summary>
        public Sha2SignatureDescription(string algorithm, string digestAlgorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
            {
                throw new ArgumentException("algorithm cannot be null or white space only");
            }

            _algorithm = algorithm;

            KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
            DigestAlgorithm = digestAlgorithm;
            FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
            DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            var deformatter = new RSAPKCS1SignatureDeformatter(key);
            deformatter.SetHashAlgorithm(_algorithm);
            return deformatter;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            var formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm(_algorithm);
            return formatter;
        }
    }

    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSAPKCS",
        Justification = "This casing is to match the existing RSAPKCS1SHA1SignatureDescription type")]
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "SHA",
        Justification = "This casing is to match the use of SHA throughout the framework")]
    public sealed class RSAPKCS1SHA256SignatureDescription : Sha2SignatureDescription
    {
        public RSAPKCS1SHA256SignatureDescription()
            : base("SHA256", typeof(SHA256Managed).FullName)
        {
        }
    }

    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSAPKCS",
        Justification = "This casing is to match the existing RSAPKCS1SHA1SignatureDescription type")]
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "SHA",
        Justification = "This casing is to match the use of SHA throughout the framework")]
    public sealed class RSAPKCS1SHA384SignatureDescription : Sha2SignatureDescription
    {
        public RSAPKCS1SHA384SignatureDescription()
            : base("SHA384", typeof(SHA384Managed).FullName)
        {
        }
    }

    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSAPKCS",
        Justification = "This casing is to match the existing RSAPKCS1SHA1SignatureDescription type")]
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "SHA",
        Justification = "This casing is to match the use of SHA throughout the framework")]
    public sealed class RSAPKCS1SHA512SignatureDescription : Sha2SignatureDescription
    {
        public RSAPKCS1SHA512SignatureDescription()
            : base("SHA512", typeof(SHA512Managed).FullName)
        {
        }
    }

    /// <summary>
    ///     configurations for XmlDSIG signing
    /// </summary>
    public class XmlDsigSigningConfig
    {
        public XmlDsigSigningConfig(string signatureMethod, string digestMethod, Type descriptionType)
        {
            if (String.IsNullOrEmpty(signatureMethod))
            {
                throw new ArgumentException("signatureMethod");
            }

            if (String.IsNullOrEmpty(digestMethod))
            {
                throw new ArgumentException("digestMethod");
            }

            if (descriptionType == null)
            {
                throw new ArgumentNullException("descriptionType");
            }

            if (!descriptionType.IsSubclassOf(typeof(SignatureDescription)))
            {
                throw new ArgumentException("descriptionType must be subclass of SignatureDescription");
            }

            SignatureDescription = descriptionType;
            SignatureMethod = signatureMethod;
            DigestMethod = digestMethod;
        }

        public string SignatureMethod { get; private set; }
        public string DigestMethod { get; private set; }
        public Type SignatureDescription { get; private set; }
    }

    /// <summary>
    ///     XmlDisig utils class wrapped registration of SHA2 alogrithms
    ///     For URI constants of Digest methods and signature method,
    ///     please refer to http://msdn.microsoft.com/en-us/library/windows/desktop/dd979768(v=vs.85).aspx
    /// </summary>
    public static class XmlDsigUtils
    {
        public const string XmlDsigMoreRsaHA256Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        public const string XmlEncSHA256Url = "http://www.w3.org/2001/04/xmlenc#sha256";

        public const string XmlDsigMoreRsaHA384Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
        public const string XmlEncSHA384Url = "http://www.w3.org/2001/04/xmldsig-more#sha384";

        public const string XmlDsigMoreRsaHA512Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
        public const string XmlEncSHA512Url = "http://www.w3.org/2001/04/xmlenc#sha512";

        private static readonly Dictionary<string, XmlDsigSigningConfig> XmlDsigconfigList =
            new Dictionary<string, XmlDsigSigningConfig>(StringComparer.InvariantCultureIgnoreCase)
            {
                {
                    Keys.SHA256,
                    new XmlDsigSigningConfig(XmlDsigMoreRsaHA256Url, XmlEncSHA256Url,
                        typeof (RSAPKCS1SHA256SignatureDescription))
                },
                {
                    Keys.SHA384,
                    new XmlDsigSigningConfig(XmlDsigMoreRsaHA384Url, XmlEncSHA384Url,
                        typeof (RSAPKCS1SHA384SignatureDescription))
                },
                {
                    Keys.SHA512,
                    new XmlDsigSigningConfig(XmlDsigMoreRsaHA512Url, XmlEncSHA512Url,
                        typeof (RSAPKCS1SHA512SignatureDescription))
                },
            };

        /// <summary>
        ///     Check if the signature method is supported
        /// </summary>
        /// <param name="signatureMethod"></param>
        /// <returns></returns>
        public static bool IsSigningMethodSupported(string signatureMethod)
        {
            return XmlDsigconfigList.Values.Any(config => config.SignatureMethod == signatureMethod);
        }

        /// <summary>
        ///     Get XmlDSig signinig configuration
        /// </summary>
        /// <param name="key">the key of configurations, it cannot be null</param>
        /// <returns>instances of XmlDsigSigningConfig, null will be returned if configuration item not found</returns>
        public static XmlDsigSigningConfig GetSigningConfig(string key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            XmlDsigSigningConfig config;
            if (!XmlDsigconfigList.TryGetValue(key, out config))
            {
                config = null;
            }

            return config;
        }

        /// <summary>
        ///     Register crypto algorithms
        /// </summary>
        public static void RegisterCryptoAlgorithms()
        {
            foreach (XmlDsigSigningConfig config in XmlDsigconfigList.Values)
            {
                CryptoConfig.AddAlgorithm(config.SignatureDescription, config.SignatureMethod);
            }
        }

        public static class Keys
        {
            public const string SHA256 = "SHA256";
            public const string SHA384 = "SHA384";
            public const string SHA512 = "SHA512";
        }
    }
}