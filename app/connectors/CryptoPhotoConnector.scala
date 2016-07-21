package connectors

import connectors.cryptophoto.CryptoPhotoUtils

trait CryptoPhotoConnector {
  val publicKey = "75c7ba97929485e85c4f29d426d5109d"
  val privateKey = "20db896029ccd1a250c0a4c6376d8ca7"
  val ip = CryptoPhotoUtils.getVisibleIp

  def session(userId: String): String = {
    val cryptoPhoto: CryptoPhotoUtils = new CryptoPhotoUtils(publicKey, privateKey)

    // Establish a CryptoPhoto session:
    val cryptoPhotoSession: CryptoPhotoUtils.CryptoPhotoResponse = cryptoPhoto.getSession(userId, ip)
    if (!cryptoPhotoSession.is("valid")) {
      println(s"CryptoPhoto session not established!%nERROR: ${cryptoPhotoSession.get("error")}, ${cryptoPhotoSession.get("signature")}")
      ""
    } else {
      cryptoPhotoSession.get("id")
    }

  }

}

object CryptoPhotoConnector extends CryptoPhotoConnector {

}
