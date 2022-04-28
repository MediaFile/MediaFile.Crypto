using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MediaFile.Crypto
{
    [Serializable]
    public class DynamicRSA_File : System.Runtime.Serialization.ISerializable
    {
        private byte[] _EnCryptoFileStream;
        public byte[] EnCryptoFileStream { get { return _EnCryptoFileStream; } set { _EnCryptoFileStream = value; } }
        private byte[] _EnCryptoPword;
        public byte[] EnCryptoPword { get { return _EnCryptoPword; } set { _EnCryptoPword = value; } }
        private string _HashPublicKey;
        public string HashPublicKey { get { return _HashPublicKey; } set { _HashPublicKey = value; } }

        /// <summary>
        /// Construtor.
        /// </summary>
        public DynamicRSA_File() { }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="cryptoStream">byte[]</param>
        /// <param name="cryptoPword">byte[]</param>
        /// <param name="hashPublicKey">string</param>
        public DynamicRSA_File(byte[] cryptoStream, byte[] cryptoPword, string hashPublicKey)
        {
            EnCryptoFileStream = cryptoStream;
            EnCryptoPword = cryptoPword;
            HashPublicKey = hashPublicKey;
        }//public DynamicRSA_File

        /// <summary>
        /// Deserialization constructor
        /// </summary>
        /// <param name="info">System.Runtime.Serialization.SerializationInfo</param>
        /// <param name="ctxt">System.Runtime.Serialization.StreamingContext</param>
        public DynamicRSA_File(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext ctxt)
        {
            //Get the values from info and assign them to the appropriate properties
            EnCryptoFileStream = (byte[])info.GetValue("EnCryptoFileStream", typeof(byte[]));
            EnCryptoPword = (byte[])info.GetValue("EnCryptoPword", typeof(byte[]));
            HashPublicKey = (string)info.GetValue("HashPublicKey", typeof(string));
        }//public DynamicRSA_File

        /// <summary>
        /// Serialization function.
        /// </summary>
        /// <param name="info">System.Runtime.Serialization.SerializationInfo</param>
        /// <param name="ctxt">System.Runtime.Serialization.StreamingContext</param>
        public void GetObjectData(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext ctxt)
        {
            info.AddValue("EnCryptoFileStream", EnCryptoFileStream);
            info.AddValue("EnCryptoPword", EnCryptoPword);
            info.AddValue("HashPublicKey", HashPublicKey);
        }//public void GetObjectData

        /// <summary>
        /// Returns bool. (override function.)
        /// </summary>
        /// <param name="obj">object of type "DynamicRSA_File".</param>
        /// <returns>bool</returns>
        public override bool Equals(object obj)
        {
            if (obj == null) { return false; }

            //Cast obj to DynamicRSA_File
            DynamicRSA_File tmpFile = obj as DynamicRSA_File;
            if (tmpFile == null) { return false; }

            if (this.EnCryptoFileStream.Length != tmpFile.EnCryptoFileStream.Length) { return false; }
            for (int i = 0; i < this.EnCryptoFileStream.Length; i++)
            {
                if (this.EnCryptoFileStream[i] != tmpFile.EnCryptoFileStream[i]) { return false; }
            }

            if (this.EnCryptoPword.Length != tmpFile.EnCryptoPword.Length) { return false; }
            for (int i = 0; i < this.EnCryptoPword.Length; i++)
            {
                if (this.EnCryptoPword[i] != tmpFile.EnCryptoPword[i]) { return false; }
            }

            if (this.HashPublicKey.Length != tmpFile.HashPublicKey.Length) { return false; }
            if (!this.HashPublicKey.Equals(tmpFile.HashPublicKey)) { return false; }

            return true;
        }//public override bool Equals

        /// <summary>
        /// Returns int GetHashCode. (override function.)
        /// </summary>
        /// <returns>int</returns>
        public override int GetHashCode()
        {
            return this.ToString().ToLower().GetHashCode();
        }//public override int GetHashCode
    }//public class DynamicRSA_File : System.Runtime.Serialization.ISerializable


    [Serializable]
    public class DynamicDvM_File : System.Runtime.Serialization.ISerializable
    {
        private DynamicRSA_File _EnCryptFileStream;
        public DynamicRSA_File EnCryptFileStream { get { return _EnCryptFileStream; }  set { _EnCryptFileStream = value; } }
        private string _OriginFileName;
        public string OriginFileName { get { return _OriginFileName; } set { _OriginFileName = value; } }
        private string _OriginFileNameExt;
        public string OriginFileNameExt { get { return _OriginFileNameExt; } set { _OriginFileNameExt = value; } }

        /// <summary>
        /// Returns bool. (override function.)
        /// </summary>
        /// <param name="obj">object of type "DynamicDvM_File".</param>
        /// <returns>bool</returns>
        public override bool Equals(object obj)
        {
            if (obj == null) { return false; }

            //Cast obj to DynamicDvM_File
            DynamicDvM_File tmpFile = obj as DynamicDvM_File;
            if (tmpFile == null) { return false; }

            if (!this.EnCryptFileStream.Equals(tmpFile.EnCryptFileStream)) { return false; }
            if (!this.OriginFileName.Equals(tmpFile.OriginFileName)) { return false; }
            if (!this.OriginFileNameExt.Equals(tmpFile.OriginFileNameExt)) { return false; }

            return true;
        }//public override bool Equals

        /// <summary>
        /// Returns int GetHashCode. (override function.)
        /// </summary>
        /// <returns>int</returns>
        public override int GetHashCode()
        {
            return this.ToString().ToLower().GetHashCode();
        }//public override int GetHashCode


        public void GetObjectData(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext ctxt)
        {
            info.AddValue("InCryptFileStream", EnCryptFileStream);
            info.AddValue("OriginFileName", OriginFileName);
            info.AddValue("OriginFileNameExt", OriginFileNameExt);
        }//public void GetObjectData
    }

    public class DynamicRSA
    {
        private static CspParameters _CspParameters;
        private static CspParameters CspParameters { get { return _CspParameters; } set { _CspParameters = value; } }
        private static RSACryptoServiceProvider _RsaProvider;
        public static RSACryptoServiceProvider RsaProvider { get { return _RsaProvider; } }
        private const int _KeySize = 8192;
        public static int KeySize { get { return _KeySize; } }

        /// <summary>
        /// Creator of a RSACryptoServiceProvider and set his parameters.
        /// </summary>
        public static void DynamicRSACreator() { AssignParameter(); }

        /// <summary>
        /// Retruns a RSACryptoServiceProvider with the parameters set.
        /// </summary>
        /// <returns>RSACryptoServiceProvider</returns>
        public static RSACryptoServiceProvider DynamicRSAConstructor()
        {
            AssignParameter();
            return RsaProvider;
        }//public static RSACryptoServiceProvider DynamicRSAConstructor

        /// <summary>
        /// Creates a RSACryptoServiceProvider and set his parameters.
        /// </summary>
        private static void AssignParameter()
        {
            const int PROVIDER_RSA_FULL = 1;
            const string CONTAINER_NAME = "KeyContainer";
            CspParameters = new CspParameters(PROVIDER_RSA_FULL);
            CspParameters.KeyContainerName = CONTAINER_NAME;
            CspParameters.Flags = CspProviderFlags.UseMachineKeyStore;
            CspParameters.ProviderName = "Microsoft Strong Cryptographic Provider";
            _RsaProvider = new RSACryptoServiceProvider(KeySize, CspParameters);
        }

        #region GetPublicKey - GetPrivateKey XmlString static functions 

        /// <summary>
        /// Returns the PublicKey as a Xmlstring
        /// </summary>
        /// <returns>XmlString</returns>
        public static string GetPublicKeyXmlString()
        {
            DynamicRSACreator();
            return RsaProvider.ToXmlString(false);
        }//public static string GetPublicKeyXmlString

        /// <summary>
        /// Returns the PrivateKey as a Xmlstring
        /// </summary>
        /// <returns>XmlString</returns>
        public static string GetPrivateKeyXmlString()
        {
            DynamicRSACreator();
            return RsaProvider.ToXmlString(true);
        }//public static string GetPrivateKeyXmlString

        #endregion

        #region EnCrytedString static functions

        /// <summary>
        /// Returns EnCryptedstring of string "inString".
        /// </summary>
        /// <param name="inString">string</param>
        /// <param name="publicKey">Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>string</returns>
        public static string CryptedString(string inString, string publicKey, bool oAEP = true)
        {
            //return null if instring or publicKey -> string.IsNullOrEmpty().
            if (string.IsNullOrEmpty(inString) || string.IsNullOrEmpty(publicKey)) { return null; }
            byte[] _CryptedByte;
            byte[] _inByte = Encoding.UTF8.GetBytes(inString);  //string to byte.

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(publicKey);
            _CryptedByte = _RsaObj.Encrypt(_inByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //byte to string and return the string.
            return Encoding.UTF8.GetString(_CryptedByte);
        }//public static string CryptedString

        /// <summary>
        /// Returns EnCryptedstring of byte[] "inByte".
        /// </summary>
        /// <param name="inByte">byte[]</param>
        /// <param name="publicKey">Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>string</returns>
        public static string CryptedString(byte[] inByte, string publicKey, bool oAEP = true)
        {
            //return null if inByte == null or publicKey == string.IsNullOrEmpty().
            if (inByte == null || string.IsNullOrEmpty(publicKey)) { return null; }
            byte[] _CryptedByte;

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(publicKey);
            _CryptedByte = _RsaObj.Encrypt(inByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //byte to string and return the string.
            return Encoding.UTF8.GetString(_CryptedByte);
        }//public static string CryptedString

        /// <summary>
        /// Returns EnCryptedstring of byte[] "inByte".
        /// </summary>
        /// <param name="inByte">byte[]</param>
        /// <param name="publicKey">byte[] of Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>string</returns>
        public static string CryptedString(byte[] inByte, byte[] publicKey, bool oAEP = true)
        {
            //return null if inByte or publicKey -> null.
            if (inByte == null || publicKey == null) { return null; }
            string _PublicKey = Encoding.UTF8.GetString(publicKey);
            byte[] _CryptedByte;

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(_PublicKey);
            _CryptedByte = _RsaObj.Encrypt(inByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //byte to string and return the string.
            return Encoding.UTF8.GetString(_CryptedByte);
        }//public static string CryptedString

        #endregion

        #region DeCryptedString static functions

        /// <summary>
        /// Returns DeCryptedString of string "inCryptedString".
        /// </summary>
        /// <param name="inCryptedString">string</param>
        /// <param name="privateKey">Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>string</returns>
        public static string DeCryptedString(string inCryptedString, string privateKey, bool oAEP = true)
        {
            //return null if inCryptedString or privateKey -> string.IsNullOrEmpty().
            if (string.IsNullOrEmpty(inCryptedString) || string.IsNullOrEmpty(privateKey)) { return null; }
            byte[] _DeCryptedByte;
            byte[] _InCryptedByte = Encoding.UTF8.GetBytes(inCryptedString);

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(privateKey);
            _DeCryptedByte = _RsaObj.Decrypt(_InCryptedByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //byte to string and return the string.
            return Encoding.UTF8.GetString(_DeCryptedByte);
        }//public static string DeCryptedString

        /// <summary>
        /// Returns DeCryptedString of byte[] "inCryptedByte".
        /// </summary>
        /// <param name="inCryptedByte">byte[]</param>
        /// <param name="privateKey">Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>string</returns>
        public static string DeCryptedString(byte[] inCryptedByte, string privateKey, bool oAEP = true)
        {
            //return null if inCryptedByte == null or publicKey == string.IsNullOrEmpty().
            if (inCryptedByte == null || string.IsNullOrEmpty(privateKey)) { return null; }
            byte[] _DeCryptedByte;

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(privateKey);
            _DeCryptedByte = _RsaObj.Decrypt(inCryptedByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //byte to string and return the string.
            return Encoding.UTF8.GetString(_DeCryptedByte);
        }//public static string DeCryptedString

        /// <summary>
        /// Returns DeCryptedString of byte[] "inCryptedByte".
        /// </summary>
        /// <param name="inByte">byte[]</param>
        /// <param name="privateKey">byte[] of Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>string</returns>
        public static string DeCryptedString(byte[] inCryptedByte, byte[] privateKey, bool oAEP = true)
        {
            //return null if inCryptedByte or publicKey -> null.
            if (inCryptedByte == null || privateKey == null) { return null; }
            byte[] _DeCryptedByte;
            string _PrivateKey = Encoding.UTF8.GetString(privateKey);

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(_PrivateKey);
            _DeCryptedByte = _RsaObj.Decrypt(inCryptedByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //byte to string and return the string.
            return Encoding.UTF8.GetString(_DeCryptedByte);
        }//public static string DeCryptedString

        #endregion

        #region EnCryptedByte static functions

        /// <summary>
        /// Returns EnCryptedByte of string "inString".
        /// </summary>
        /// <param name="inString">string</param>
        /// <param name="publicKey">Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>byte[]</returns>
        public static byte[] CryptedByte(string inString, string publicKey, bool oAEP = true)
        {
            //return null if instring or publicKey -> string.IsNullOrEmpty().
            if (string.IsNullOrEmpty(inString) || string.IsNullOrEmpty(publicKey)) { return null; }
            byte[] _CryptedByte;
            byte[] _inByte = Encoding.UTF8.GetBytes(inString);  //string to byte.

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(publicKey);
            _CryptedByte = _RsaObj.Encrypt(_inByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //byte to string and return the byte.
            return _CryptedByte;
        }//public static byte[] CryptedByte

        /// <summary>
        /// Returns EnCryptedByte of byte[] "inByte".
        /// </summary>
        /// <param name="inByte">byte[]</param>
        /// <param name="publicKey">Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>byte[]</returns>
        public static byte[] CryptedByte(byte[] inByte, string publicKey, bool oAEP = true)
        {
            //return null if inByte == null or publicKey == string.IsNullOrEmpty().
            if (inByte == null || string.IsNullOrEmpty(publicKey)) { return null; }
            byte[] _CryptedByte;

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(publicKey);
            _CryptedByte = _RsaObj.Encrypt(inByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //return the byte.
            return _CryptedByte;
        }//public static byte[] CryptedByte

        /// <summary>
        /// Returns EnCryptedByte of byte[] "inByte".
        /// </summary>
        /// <param name="inByte">byte[]</param>
        /// <param name="publicKey">byte[] of Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>byte[]</returns>
        public static byte[] CryptedByte(byte[] inByte, byte[] publicKey, bool oAEP = true)
        {
            //return null if inByte or publicKey -> null.
            if (inByte == null || publicKey == null) { return null; }
            string _PublicKey = Encoding.UTF8.GetString(publicKey);
            byte[] _CryptedByte;

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(_PublicKey);
            _CryptedByte = _RsaObj.Encrypt(inByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //return the byte.
            return _CryptedByte;
        }//public static byte[] CryptedByte

        #endregion

        #region DeCryptedByte static functions

        /// <summary>
        /// Returns DeCryptedByte of string "inCryptedString".
        /// </summary>
        /// <param name="inCryptedString">string</param>
        /// <param name="privateKey">Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>byte[]</returns>
        public static byte[] DeCryptedByte(string inCryptedString, string privateKey, bool oAEP = true)
        {
            //return null if inCryptedString or privateKey -> string.IsNullOrEmpty().
            if (string.IsNullOrEmpty(inCryptedString) || string.IsNullOrEmpty(privateKey)) { return null; }
            byte[] _DeCryptedByte;
            byte[] _InCryptedByte = Encoding.UTF8.GetBytes(inCryptedString);

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(privateKey);
            _DeCryptedByte = _RsaObj.Decrypt(_InCryptedByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //return the byte.
            return _DeCryptedByte;
        }//public static byte[] DeCryptedByte

        /// <summary>
        /// Returns DeCryptedByte of byte[] "inCryptedByte".
        /// </summary>
        /// <param name="inCryptedByte">byte[]</param>
        /// <param name="privateKey">Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>byte[]</returns>
        public static byte[] DeCryptedByte(byte[] inCryptedByte, string privateKey, bool oAEP = true)
        {
            //return null if inCryptedByte == null or publicKey == string.IsNullOrEmpty().
            if (inCryptedByte == null || string.IsNullOrEmpty(privateKey)) { return null; }
            byte[] _DeCryptedByte;

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(privateKey);
            _DeCryptedByte = _RsaObj.Decrypt(inCryptedByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //return the byte.
            return _DeCryptedByte;
        }//public static byte[] DeCryptedByte

        /// <summary>
        /// Returns DeCryptedByte of byte[] "inCryptedByte".
        /// </summary>
        /// <param name="inCryptedByte">byte[]</param>
        /// <param name="privateKey">byte[] of Xmlstring</param>
        /// <param name="oAEP = true">bool: enter "false" if operatingsystem is older then XP.</param>
        /// <returns>byte[]</returns>
        public static byte[] DeCryptedByte(byte[] inCryptedByte, byte[] privateKey, bool oAEP = true)
        {
            //return null if inCryptedByte or publicKey -> null.
            if (inCryptedByte == null || privateKey == null) { return null; }
            byte[] _DeCryptedByte;
            string _PrivateKey = Encoding.UTF8.GetString(privateKey);

            //Create RSACryptoServiceProvider and inCrypted the byte (inString).
            RSACryptoServiceProvider _RsaObj = DynamicRSA.DynamicRSAConstructor();
            _RsaObj.FromXmlString(_PrivateKey);
            _DeCryptedByte = _RsaObj.Decrypt(inCryptedByte, oAEP);

            //Dispose and Clear RSACryptoServiceProvider.
            _RsaObj.Dispose();
            _RsaObj.Clear();

            //return the byte.
            return _DeCryptedByte;
        }//public static byte[] DeCryptedByte

        #endregion

    }//Class DynamicRSA


    public class EAS_File
    {
        private static readonly string saltString = "Salt0fTh3Earth";
        private static byte[] saltBytes = Encoding.ASCII.GetBytes(saltString);
        private static readonly byte[] VIKeyBytes = Encoding.ASCII.GetBytes("@1B2c3D4e5F6g7H8");

        private static void GetsaltBytes(string pword)
        {
            string printsalt = pword + saltString;
            saltBytes = Encoding.ASCII.GetBytes(printsalt);
        }

        #region CryptTheByte - DeCryptTheByte static functions

        /// <summary>
        /// Returns EnCryptedByte of byte[] "bytesToBeEncrypted".
        /// </summary>
        /// <param name="bytesToBeEncrypted">bytes[]</param>
        /// <param name="pWord">bytes[]</param>
        /// <returns>byte[]</returns>
        private static byte[] CryptTheByte(byte[] bytesToBeEncrypted, byte[] pWord)
        {
            byte[] _CryptoByteTest = bytesToBeEncrypted;
            byte[] _CryptoByte = null;

            using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(pWord, saltBytes, 2500);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cryptoStream.Close();
                    }
                    AES.Dispose();
                    AES.Clear();
                }
                _CryptoByte = memoryStream.ToArray();
                memoryStream.Close();
            }

            if (_CryptoByte.SequenceEqual(_CryptoByteTest)) { return null; }
            return _CryptoByte;
        }//private static byte[] CryptTheByte

        /// <summary>
        /// Returns DeCryptedByte of byte[] "bytesToBeDecrypted".
        /// </summary>
        /// <param name="bytesToBeDecrypted">butes[]</param>
        /// <param name="pWord">butes[]</param>
        /// <returns>byte[]</returns>
        private static byte[] DecryptTheByte(byte[] bytesToBeDecrypted, byte[] pWord)
        {
            byte[] deCryptoFileByteTest = bytesToBeDecrypted;
            byte[] deCryptoFileByte = null;

            using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(pWord, saltBytes, 2500);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (CryptoStream deCryptoStream = new CryptoStream(memoryStream, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        deCryptoStream.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        deCryptoStream.Close();
                    }
                    AES.Dispose();
                    AES.Clear();
                }
                deCryptoFileByte = memoryStream.ToArray();
                memoryStream.Close();
            }

            if (deCryptoFileByte.SequenceEqual(deCryptoFileByteTest)) { return null; }
            return deCryptoFileByte;
        }//private static byte[] DecryptTheByte

        #endregion

        #region EnCryptFile - DeCryptFile static functions

        /// <summary>
        /// Creates an EnCryptedFile "outCryptFile" from file "inFile". (Filenames are inc. path.)
        /// </summary>
        /// <param name="inFile">string inFileName (inc. Path.)</param>
        /// <param name="outCryptFile">string outCryptedFileName (inc. Path.)</param>
        /// <param name="pWord">string</param>
        public static void CryptFile(string inFile, string outCryptFile, string pWord)
        {
            GetsaltBytes(pWord);

            if (System.IO.File.Exists(inFile))
            {
                byte[] inBytes = System.IO.File.ReadAllBytes(inFile);
                byte[] pword = Encoding.UTF8.GetBytes(pWord);

                byte[] cryptBytes = CryptTheByte(inBytes, pword);

                System.IO.File.WriteAllBytes(outCryptFile, cryptBytes);
            }
            else //File Doenst exist throw
            {
                throw new System.IO.IOException("InPutFileDoesntExists");
            }
        }//public static void CryptFile

        /// <summary>
        /// Creates an DeCryptedFile "outFile" from inCryptedfile "inCryptFile". (Filenames are inc. path.)
        /// </summary>
        /// <param name="inCryptFile">string inCryptedFileName (inc. path.)</param>
        /// <param name="outFile">string outFileName (inc. path.)</param>
        /// <param name="pWord">string</param>
        public static void DecryptFile(string inCryptFile, string outFile, string pWord)
        {
            GetsaltBytes(pWord);

            if (System.IO.File.Exists(inCryptFile))
            {
                byte[] inBytes = System.IO.File.ReadAllBytes(inCryptFile);
                byte[] pword = Encoding.UTF8.GetBytes(pWord);

                byte[] deCryptBytes = DecryptTheByte(inBytes, pword);

                System.IO.File.WriteAllBytes(outFile, deCryptBytes);
            }
            else //File Doenst exist throw
            {
                throw new System.IO.IOException("InPutCryptFileDoesntExists");
            }
        }//public static void DecryptFile

        #endregion

        #region HashedString static functions

        /// <summary>
        /// Returns HashedString from string "plainText".
        /// </summary>
        /// <param name="plainText">string</param>
        /// <param name="passWordHash">string</param>
        /// <returns>string</returns>
        private static string HashString(string plainText, string passWordHash)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keyBytes = new Rfc2898DeriveBytes(passWordHash, saltBytes).GetBytes(256 / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.Zeros };
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, VIKeyBytes);

            byte[] cipherTextBytes;

            using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cipherTextBytes = memoryStream.ToArray();
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }

            return Convert.ToBase64String(cipherTextBytes);
        }//private static string HashString

        /// <summary>
        /// Returns HashedString from byte[] "plainByte".
        /// </summary>
        /// <param name="plainByte">byte[]</param>
        /// <param name="passWordHash">string</param>
        /// <returns>string</returns>
        private static string HashString(byte[] plainByte, string passWordHash)
        {
            return HashString(Encoding.UTF8.GetString(plainByte), passWordHash);
        }//private static string HashString

        /// <summary>
        /// Returns HashedString from byte[] "plainByte".
        /// </summary>
        /// <param name="plainByte">byte[]</param>
        /// <param name="passWordHash">byte[]</param>
        /// <returns>string</returns>
        private static string HashString(byte[] plainByte, byte[] passWordHash)
        {
            return HashString(Encoding.UTF8.GetString(plainByte), Encoding.UTF8.GetString(passWordHash));
        }//private static string HashString

        #endregion

        #region DeHashedString static functions

        /// <summary>
        /// Returns DeHashedString from string "hashText".
        /// </summary>
        /// <param name="hashText">string</param>
        /// <param name="passWordHash">string</param>
        /// <returns>string</returns>
        private static string DeHashString(string hashText, string passWordHash)
        {
            byte[] plainTextBytes = null;
            int decryptedByteCount;

            byte[] keyBytes = new Rfc2898DeriveBytes(passWordHash, saltBytes).GetBytes(256 / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.None };
            var decryptor = symmetricKey.CreateDecryptor(keyBytes, VIKeyBytes);

            byte[] cipherTextBytes = Convert.FromBase64String(hashText);

            using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream(cipherTextBytes))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    plainTextBytes = new byte[cipherTextBytes.Length];
                    decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }

            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount).TrimEnd("\0".ToCharArray());
        }//private static string DeHashString

        /// <summary>
        /// Returns DeHashedString from byte[] "hashByte".
        /// </summary>
        /// <param name="hashByte">byte[]</param>
        /// <param name="passWordHash">string</param>
        /// <returns>string</returns>
        private static string DeHashString(byte[] hashByte, string passWordHash)
        {
            return DeHashString(Encoding.UTF8.GetString(hashByte), passWordHash);
        }//private static string DeHashString

        /// <summary>
        /// Returns DeHashedString from byte[] "hashByte".
        /// </summary>
        /// <param name="hashByte">byte[]</param>
        /// <param name="passWordHash">byte[]</param>
        /// <returns>string</returns>
        private static string DeHashString(byte[] hashByte, byte[] passWordHash)
        {
            return DeHashString(Encoding.UTF8.GetString(hashByte), Encoding.UTF8.GetString(passWordHash));
        }//private static string DeHashString

        #endregion

        #region HashedByte static functions

        /// <summary>
        /// Returns HashedByte from string "plainText".
        /// </summary>
        /// <param name="plainText">string</param>
        /// <param name="passWordHash">string</param>
        /// <returns>byte[]</returns>
        private static byte[] HashByte(string plainText, string passWordHash)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keyBytes = new Rfc2898DeriveBytes(passWordHash, saltBytes).GetBytes(256 / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.Zeros };
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, VIKeyBytes);

            byte[] cipherTextBytes;

            using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cipherTextBytes = memoryStream.ToArray();
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }

            return cipherTextBytes;
        }//private static byte[] HashByte

        /// <summary>
        /// Returns HashedByte from byte[] "plainByte".
        /// </summary>
        /// <param name="plainByte">byte[]</param>
        /// <param name="passWordHash">string</param>
        /// <returns>byte[]</returns>
        private static byte[] HashByte(byte[] plainByte, string passWordHash)
        {
            return HashByte(Encoding.UTF8.GetString(plainByte), passWordHash);
        }//private static byte[] HashByte

        /// <summary>
        /// Returns HashedByte from byte[] "plainByte".
        /// </summary>
        /// <param name="plainByte">byte[]</param>
        /// <param name="passWordHash">byte[]</param>
        /// <returns>byte[]</returns>
        private static byte[] HashByte(byte[] plainByte, byte[] passWordHash)
        {
            return HashByte(Encoding.UTF8.GetString(plainByte), Encoding.UTF8.GetString(passWordHash));
        }//private static byte[] HashByte

        #endregion

        #region DeHashedByte static functions

        /// <summary>
        /// Returns DeHashedByte from string "hashText".
        /// </summary>
        /// <param name="hashText">string</param>
        /// <param name="passWordHash">string</param>
        /// <returns>byte[]</returns>
        private static byte[] DeHashByte(string hashText, string passWordHash)
        {
            byte[] plainTextBytes = null;
            int decryptedByteCount;

            byte[] keyBytes = new Rfc2898DeriveBytes(passWordHash, saltBytes).GetBytes(256 / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.None };
            var decryptor = symmetricKey.CreateDecryptor(keyBytes, VIKeyBytes);

            byte[] cipherTextBytes = Convert.FromBase64String(hashText);

            using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream(cipherTextBytes))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    plainTextBytes = new byte[cipherTextBytes.Length];
                    decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }

            return plainTextBytes;
        }//private static byte[] DeHashByte

        /// <summary>
        /// Returns DeHashedByte from byte[] "hashByte".
        /// </summary>
        /// <param name="hashByte">byte[]</param>
        /// <param name="passWordHash">string</param>
        /// <returns>byte[]</returns>
        private static byte[] DeHashByte(byte[] hashByte, string passWordHash)
        {
            return DeHashByte(Encoding.UTF8.GetString(hashByte), passWordHash);
        }//private static byte[] DeHashByte

        /// <summary>
        /// Returns DeHashedByte from byte[] "hashByte".
        /// </summary>
        /// <param name="hashByte">byte[]</param>
        /// <param name="passWordHash">byte[]</param>
        /// <returns>byte[]</returns>
        private static byte[] DeHashByte(byte[] hashByte, byte[] passWordHash)
        {
            return DeHashByte(Encoding.UTF8.GetString(hashByte), Encoding.UTF8.GetString(passWordHash));
        }//private static byte[] DeHashByte

        #endregion

        #region RSACryptFile - RSADeCryptFile static functions

        /// <summary>
        /// Creates a RSAEnCryptedFile "outCryptFile" from file "inFile". (Filenames are inc. path.)
        /// </summary>
        /// <param name="inFile">string of inFileName (inc. Path.)</param>
        /// <param name="outCryptFile">string of outEnCryptedFileName (inc. Path.)</param>
        /// <param name="pWord">string</param>
        /// <param name="publicKey">Xmlstring</param>
        public static void RSACryptFile(string inFile, string outCryptFile, string pWord, string publicKey)
        {
            string _HashPublicKey;
            byte[] _CryptoFileStream;
            DynamicRSA_File DRsa_File = new DynamicRSA_File();

            if (System.IO.File.Exists(inFile) && !string.IsNullOrEmpty(publicKey) && !string.IsNullOrEmpty(pWord))
            {
                DynamicRSA.DynamicRSACreator();
                RSACryptoServiceProvider RSACrypto = DynamicRSA.RsaProvider;
                RSACrypto.FromXmlString(publicKey);

                byte[] _bytepWord = Encoding.UTF8.GetBytes(pWord);
                byte[] _byteCryptedpWord = RSACrypto.Encrypt(_bytepWord, true);
                byte[] _byteInFile = System.IO.File.ReadAllBytes(inFile);

                _HashPublicKey = HashString(RSACrypto.ToXmlString(false), pWord);
                _CryptoFileStream = CryptTheByte(_byteInFile, _byteCryptedpWord);

                DRsa_File.EnCryptoFileStream = _CryptoFileStream;
                DRsa_File.EnCryptoPword = _byteCryptedpWord;
                DRsa_File.HashPublicKey = _HashPublicKey;

                try
                {
                    if (!System.IO.File.Exists(outCryptFile))
                    {
                        using (System.IO.Stream stream = System.IO.File.Open(outCryptFile, System.IO.FileMode.Create))
                        {
                            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bformatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();

                            bformatter.Serialize(stream, DRsa_File);
                            stream.Close();
                        }
                    }
                    else
                    {
                        throw new System.IO.IOException("OutPutFileExists");
                    }
                }
                finally
                {
                    RSACrypto.Dispose();
                    RSACrypto.Clear();
                }
            }
            else //File Doenst exist throw
            {
                if (!System.IO.File.Exists(inFile)) { throw new System.IO.IOException("InPutFileDoesntExists"); }
                if (string.IsNullOrEmpty(publicKey)) { throw new Exception("PublicKeyMissing"); }
                if (string.IsNullOrEmpty(pWord)) { throw new Exception("PasswordMissing"); }
            }
        }//public void RSACryptFile

        /// <summary>
        /// Creates a RSADeCryptedFile "outFile" from EnCryptedfile "inCryptFile". (Filenames are inc. path.)
        /// </summary>
        /// <param name="inCryptFile">string of inEnCryptedFileName (inc. path.)</param>
        /// <param name="outFile">string of outFileName (inc. path.)</param>
        /// <param name="pWord">string</param>
        /// <param name="privateKey">Xmlstring</param>
        public static void RSADecryptFile(string inCryptFile, string outFile, string pWord, string privateKey)
        {
            string _HashPublicKey;
            byte[] _deCryptedBytes;
            byte[] _CryptedpWord;
            DynamicRSA_File DRsa_File;

            if (System.IO.File.Exists(inCryptFile) && !string.IsNullOrEmpty(privateKey) && !string.IsNullOrEmpty(pWord))
            {
                DynamicRSA.DynamicRSACreator();
                RSACryptoServiceProvider RSACrypto = DynamicRSA.RsaProvider;

                try
                {
                    using (System.IO.Stream stream = System.IO.File.Open(inCryptFile, System.IO.FileMode.Open))
                    {
                        System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bformatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();

                        DRsa_File = (DynamicRSA_File)bformatter.Deserialize(stream);
                        stream.Close();
                    }

                    RSACrypto.FromXmlString(privateKey);

                    _CryptedpWord = DRsa_File.EnCryptoPword;
                    _HashPublicKey = DRsa_File.HashPublicKey;

                    if (RSACrypto.ToXmlString(false).Equals(DeHashString(_HashPublicKey, pWord)) && pWord.Equals(Encoding.UTF8.GetString(RSACrypto.Decrypt(_CryptedpWord, false))))
                    {
                        _deCryptedBytes = DecryptTheByte(DRsa_File.EnCryptoFileStream, _CryptedpWord);
                        System.IO.File.WriteAllBytes(outFile, _deCryptedBytes);
                    }
                    else
                    {
                        throw new Exception("PasswordOrPrivateKeyInValid");
                    }
                }
                finally
                {
                    RSACrypto.Dispose();
                    RSACrypto.Clear();
                }
            }
            else //File Doenst exist throw
            {
                if (!System.IO.File.Exists(inCryptFile)) { throw new System.IO.IOException("InPutFileDoesntExists"); }
                if (string.IsNullOrEmpty(privateKey) || string.IsNullOrEmpty(pWord)) { throw new Exception("PasswordOrPrivateKeyMissing"); }
            }
        }//public static void RSADecryptFile

        #endregion

        #region DvMCryptObjFile - DvMDeCryptObjFile static functions

        public static void DvmCryptObjFile(string inFile, string outCryptFolder, string pWord, string publicKey)
        {
            if (System.IO.File.Exists(inFile) && !string.IsNullOrEmpty(publicKey) && !string.IsNullOrEmpty(pWord))
            {
                //Get the nameIndex from the filename.
                string FileName = inFile.Trim();
                int FileNamePoint = FileName.LastIndexOf(".");
                int FileNameBrac = FileName.LastIndexOf("\\");
                //

                try
                {
                    if (!System.IO.Directory.Exists(outCryptFolder))
                    {
                        using (System.IO.Stream stream = System.IO.File.Open(outCryptFolder + FileName.Substring(FileNameBrac + 1, FileNamePoint - 1) + ".DvMCrypt", System.IO.FileMode.Create))
                        {
                            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bformatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();

                            bformatter.Serialize(stream, DvMCryptFileInStreamOut(inFile, pWord, publicKey);
                            stream.Close();
                        }
                    }
                    else
                    {
                        throw new System.IO.IOException("OutPutFileExists");
                    }
                }
                finally
                { }
            }
            else //File Doenst exist throw
            {
                if (!System.IO.File.Exists(inFile)) { throw new System.IO.IOException("InPutFileDoesntExists"); }
                if (string.IsNullOrEmpty(publicKey)) { throw new Exception("PublicKeyMissing"); }
                if (string.IsNullOrEmpty(pWord)) { throw new Exception("PasswordMissing"); }
            }
        }

        public static void DvMDeCryptObjFile(string inCryptFile, string outFile, string pWord, string privateKey)
        {

        }

        #endregion

        #region DvmCryptFileInStreamOut - DvMDeCryptFileInStreamOut

        public static System.IO.Stream DvMCryptFileInStreamOut(string inFile, string pWord, string publicKey)
        {
            string _HashPublicKey;
            byte[] _CryptoFileStream;
            DynamicRSA_File DRsa_File = new DynamicRSA_File();
            DynamicDvM_File DDvm_File = new DynamicDvM_File();

            DynamicRSA.DynamicRSACreator();
            RSACryptoServiceProvider RSACrypto = DynamicRSA.RsaProvider;
            RSACrypto.FromXmlString(publicKey);

            try
            {
                byte[] _bytepWord = Encoding.UTF8.GetBytes(pWord);
                byte[] _byteCryptedpWord = RSACrypto.Encrypt(_bytepWord, true);
                byte[] _byteInFile = System.IO.File.ReadAllBytes(inFile);

                _HashPublicKey = HashString(RSACrypto.ToXmlString(false), pWord);
                _CryptoFileStream = CryptTheByte(_byteInFile, _byteCryptedpWord);

                DRsa_File.EnCryptoFileStream = _CryptoFileStream;
                DRsa_File.EnCryptoPword = _byteCryptedpWord;
                DRsa_File.HashPublicKey = _HashPublicKey;

                DDvm_File.EnCryptFileStream = DRsa_File;
            }
            finally
            {
                RSACrypto.Dispose();
                RSACrypto.Clear();
            }

        }

        public static System.IO.Stream DvMDeCryptFileInStreamOut(string inCryptFile, string pWord, string privateKey)
        {
            return null;
        }

        #endregion



        #region RSACryptObj - RSADeCryptObj static functions

        /// <summary>
        /// Returns a DynamicRSA_File (EnCrypted.) from Serializable-object "obj".
        /// </summary>
        /// <param name="obj">Object : ISerializable</param>
        /// <param name="pWord">string</param>
        /// <param name="publicKey">Xmlstring</param>
        /// <returns>DynamicRSA_File : ISerializable</returns>
        public static DynamicRSA_File RSACryptObj(object obj, string pWord, string publicKey)
        {
            DynamicRSA_File DRsa_Obj = new DynamicRSA_File();

            if (obj != null && !string.IsNullOrEmpty(publicKey) && !string.IsNullOrEmpty(pWord))
            {
                DynamicRSA.DynamicRSACreator();
                RSACryptoServiceProvider RSACrypto = DynamicRSA.RsaProvider;

                try
                {
                    RSACrypto.FromXmlString(publicKey);

                    DRsa_Obj.EnCryptoFileStream = RSACryptByte(obj, pWord, publicKey);
                    DRsa_Obj.EnCryptoPword = RSACrypto.Encrypt(Encoding.UTF8.GetBytes(pWord), true);
                    DRsa_Obj.HashPublicKey = HashString(RSACrypto.ToXmlString(false), pWord);
                }
                catch
                {
                    DRsa_Obj = null;
                }
                finally
                {
                    RSACrypto.Dispose();
                    RSACrypto.Clear();
                }
            }
            else //Object or Strings doesn't exist throw Exception
            {
                if (obj == null) { throw new Exception("InPutObjectDoesntExists"); }
                if (string.IsNullOrEmpty(publicKey) || string.IsNullOrEmpty(pWord)) { throw new Exception("PasswordOrPublicKeyMissing"); }
            }
            return DRsa_Obj;
        }//public static DynamicRSA_File RSACryptObj

        /// <summary>
        /// Returns a Serializable-object (DeCrypted.) from Serializable-object "inCryptObj" (of type "DynamicRSA_File".).
        /// </summary>
        /// <param name="inCryptObj">DynamicRSA_File : ISerializable</param>
        /// <param name="pWord">string</param>
        /// <param name="privateKey">Xmlstring</param>
        /// <returns>Object : ISerializable</returns>
        public static object RSADeCryptObj(object inCryptObj, string pWord, string privateKey)
        {
            object _fileObj = null;
            DynamicRSA_File DRsa_Obj = inCryptObj as DynamicRSA_File;

            if (DRsa_Obj != null && !string.IsNullOrEmpty(privateKey) && !string.IsNullOrEmpty(pWord))
            {
                try
                {
                    byte[] _deCryptedBytes = RSADeCryptByte(inCryptObj, pWord, privateKey);
                    using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream(_deCryptedBytes))
                    {
                        System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bformatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                        _fileObj = (object)bformatter.Deserialize(memoryStream);
                    }
                }
                catch
                {
                    _fileObj = null;
                }
            }
            else //Object or Strings doesn't exist throw Exception
            {
                if (DRsa_Obj == null) { throw new Exception("InPutObjectDoesntExists"); }
                if (string.IsNullOrEmpty(privateKey) || string.IsNullOrEmpty(pWord)) { throw new Exception("PasswordOrPrivateKeyMissing"); }
            }
            return _fileObj;
        }//public static object RSADeCryptObj

        #endregion

        #region private RSA Helpers

        /// <summary>
        /// Returns a byte[] (DeCrypted.) from Serializable-object "inCryptObj" (of type "DynamicRSA_File".).
        /// </summary>
        /// <param name="inCryptObj">DynamicRSA_File : ISerializable</param>
        /// <param name="pWord">string</param>
        /// <param name="privateKey">Xmlstring</param>
        /// <returns>DeCrypeted byte[]</returns>
        private static byte[] RSADeCryptByte(object inCryptObj, string pWord, string privateKey)
        {
            byte[] _deCryptedBytes = null;

            try
            {
                    _deCryptedBytes = DecryptTheByte(GetDeCryptedRSA_Obj(inCryptObj, pWord, privateKey).EnCryptoFileStream, EAS_File.RSACryptpWordFromObj(inCryptObj, privateKey));
            }
            catch
            {
                _deCryptedBytes = null;
            }
            return _deCryptedBytes;
        }

        /// <summary>
        /// Returns a byte[] (EnCrypted.) from Serializable-object "obj".
        /// </summary>
        /// <param name="Obj">DynamicRSA_File : ISerializable</param>
        /// <param name="pWord">string</param>
        /// <param name="publicKey">Xmlstring</param>
        /// <returns>Crypted byte[]</returns>
        private static byte[] RSACryptByte(object Obj, string pWord, string publicKey)
        {
            byte[] _CryptedBytes = null;

            DynamicRSA.DynamicRSACreator();
            RSACryptoServiceProvider RSACrypto = DynamicRSA.RsaProvider;

            try
            {
                RSACrypto.FromXmlString(publicKey);

                byte[] _byteCryptedpWord = RSACrypto.Encrypt(Encoding.UTF8.GetBytes(pWord), true);
                byte[] _byteStream = ObjectToByteArray(Obj);

                _CryptedBytes = CryptTheByte(_byteStream, _byteCryptedpWord);
            }
            catch
            {
                _CryptedBytes = null;
            }
            finally
            {
                RSACrypto.Dispose();
                RSACrypto.Clear();
            }

            return _CryptedBytes;
        }

        /// <summary>
        /// Returns a DynamicRSA_File (DeCrypted.) from Serializable-object "inCryptObj".
        /// </summary>
        /// <param name="inCryptObj">DynamicRSA_File : ISerializable</param>
        /// <param name="pWord">string</param>
        /// <param name="publicKey">Xmlstring</param>
        /// <returns>DynamicRSA_File : ISerializable</returns>
        private static DynamicRSA_File GetDeCryptedRSA_Obj(object inCryptObj, string pWord, string privateKey)
        {
            DynamicRSA_File DRsa_Obj = inCryptObj as DynamicRSA_File;

            if (DRsa_Obj != null && !string.IsNullOrEmpty(privateKey) && !string.IsNullOrEmpty(pWord))
            {
                DynamicRSA.DynamicRSACreator();
                RSACryptoServiceProvider RSACrypto = DynamicRSA.RsaProvider;

                try
                {
                    RSACrypto.FromXmlString(privateKey);

                    byte[] _CryptedpWord = DRsa_Obj.EnCryptoPword;
                    string _HashPublicKey = DRsa_Obj.HashPublicKey;

                    if (!RSACrypto.ToXmlString(false).Equals(DeHashString(_HashPublicKey, pWord)) && !pWord.Equals(Encoding.UTF8.GetString(RSACrypto.Decrypt(_CryptedpWord, false))))
                    {
                        throw new Exception("PasswordOrPrivateKeyInValid");
                    }
                }
                catch
                {
                    DRsa_Obj = null;
                }
                finally
                {
                    RSACrypto.Dispose();
                    RSACrypto.Clear();
                }
            }
            else //Object or Strings doesn't exist throw Exception
            {
                if (DRsa_Obj == null) { throw new Exception("InPutObjectDoesntExists"); }
                if (string.IsNullOrEmpty(privateKey) || string.IsNullOrEmpty(pWord)) { throw new Exception("PasswordOrPrivateKeyMissing"); }
            }
            return DRsa_Obj;
        }


        /// <summary>
        /// Returns the CrypetedpWord byte[] form an DynamicRSA_File object.
        /// </summary>
        /// <param name="inCryptObj">DynamicRSA_File : ISerializable</param>
        /// <param name="privateKey">Xmlstring</param>
        /// <returns>byte[]</returns>
        private static byte[] RSACryptpWordFromObj(object inCryptObj, string privateKey)
        {
            byte[] _CryptedpWord = null;
            DynamicRSA_File DRsa_Obj = inCryptObj as DynamicRSA_File;

            if (DRsa_Obj != null && !string.IsNullOrEmpty(privateKey))
            {
                DynamicRSA.DynamicRSACreator();
                RSACryptoServiceProvider RSACrypto = DynamicRSA.RsaProvider;

                RSACrypto.FromXmlString(privateKey);
                _CryptedpWord = DRsa_Obj.EnCryptoPword;
            }

            return _CryptedpWord;
        }

        #endregion

        /// <summary>
        /// Return byte[] from object "obj".
        /// </summary>
        /// <param name="obj">Object : ISerializable</param>
        /// <returns>byte[]</returns>
        private static byte[] ObjectToByteArray(object obj)
        {
            byte[] _retourObj = null;

            if (obj == null) { return _retourObj; }
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            using (System.IO.MemoryStream memoryStream = new System.IO.MemoryStream())
            {
                binaryFormatter.Serialize(memoryStream, obj);
                _retourObj = memoryStream.ToArray();
            }

            return _retourObj;
        }//private static byte[] ObjectToByteArray

    }//private class EAS_File

}//namespace MediaFile.Crypto