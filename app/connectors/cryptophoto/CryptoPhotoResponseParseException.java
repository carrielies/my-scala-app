package connectors.cryptophoto;

/**
 * Thrown when a CryptoPhoto API response body is parsed unsuccessfully.
 *
 * @author <a href="http://cryptophoto.com">CryptoPhoto</a>,
 *         <a href="mailto:tech@cryptophoto.com">tech@cryptophoto.com</a>
 * @version 1.20140728
 */
public class CryptoPhotoResponseParseException extends Exception {

    public CryptoPhotoResponseParseException() {}

    public CryptoPhotoResponseParseException(String message) { super(message); }

    public CryptoPhotoResponseParseException(Throwable cause) { super(cause); }

    public CryptoPhotoResponseParseException(String message, Throwable cause) { super(message, cause); }
}
