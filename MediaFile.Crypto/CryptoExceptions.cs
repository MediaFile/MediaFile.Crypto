namespace MediaFile.Crypto
{
    /// <summary>
    /// The exception that is thrown when an unexpected operation occurs during a cryptographic operation.
    /// Inheritance from System.Security.Cryptography.CryptographicUnexpectedOperationException
    /// </summary>
    [System.SerializableAttribute]
    [System.Runtime.InteropServices.ComVisibleAttribute(true)]
    public class CryptoKeySizeUnexpectedOperationException: System.Security.Cryptography.CryptographicUnexpectedOperationException
    {
        /// <summary>
        /// Initializes a new instance of the CryptoKeySizeUnexpectedOperationException class with default properties.
        /// </summary>
        public CryptoKeySizeUnexpectedOperationException()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the CryptoKeySizeUnexpectedOperationException class with serialized data.
        /// </summary>
        /// <param name="info">SerializationInfo</param>
        /// <param name="context">streamcontext</param>
        public CryptoKeySizeUnexpectedOperationException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        {

        }

        /// <summary>
        /// Initializes a new instance of the CryptoKeySizeUnexpectedOperationException class with a specified error message.
        /// </summary>
        /// <param name="message">custom error message string</param>
        public CryptoKeySizeUnexpectedOperationException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the CryptoKeySizeUnexpectedOperationException class with a specified error message and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">custom error message string</param>
        /// <param name="ex">Inner exception reference</param>
        public CryptoKeySizeUnexpectedOperationException(string message, System.Exception ex)
            : base(message, ex)
        {
        }

        /// <summary>
        /// Initializes a new instance of the CryptoKeySizeUnexpectedOperationException class with a specified error message in the specified format.
        /// </summary>
        /// <param name="dateFormat">string dateFormat = "{0:t}"</param>
        /// <param name="timeStamp">string timeStamp = (DateTime.Now.ToString())</param>
        public CryptoKeySizeUnexpectedOperationException(string dateFormat, string timeStamp)
            : base(dateFormat, timeStamp)
        {
        }
    }//class
}//namespace