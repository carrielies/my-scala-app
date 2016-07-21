package connectors.cryptophoto;

public class CryptoPhotoInvalidSession extends Exception {

    private CryptoPhotoUtils.CryptoPhotoResponse cryptoPhotoSession;

    public CryptoPhotoInvalidSession(CryptoPhotoUtils.CryptoPhotoResponse cryptoPhotoSession) {
        this();
        this.cryptoPhotoSession = cryptoPhotoSession;
    }

    public CryptoPhotoInvalidSession() {
        super("no valid CryptoPhoto session could be established");
    }

    @Override
    public String getMessage() {
        if (cryptoPhotoSession == null) {
            return super.getMessage();
        }
        String error = cryptoPhotoSession.get("error");
        return error == null ? super.getMessage() : super.getMessage() + ": " + error;
    }
}
