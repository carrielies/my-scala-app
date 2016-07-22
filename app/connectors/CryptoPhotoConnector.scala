package connectors

import connectors.cryptophoto.CryptoPhotoUtils
import models.Crypto

trait CryptoPhotoConnector {
  val publicKey = "75c7ba97929485e85c4f29d426d5109d"
  val privateKey = "20db896029ccd1a250c0a4c6376d8ca7"
  val ip = CryptoPhotoUtils.getVisibleIp
  val cryptoPhoto: CryptoPhotoUtils = new CryptoPhotoUtils(publicKey, privateKey)

  def session(userId: String): (Option[String], Boolean, Option[String]) = {

    // Establish a CryptoPhoto session:
    val cryptoPhotoSession: CryptoPhotoUtils.CryptoPhotoResponse = cryptoPhoto.getSession(userId, ip)

    println(s"CryptoPhoto session is_valid => ${cryptoPhotoSession.is("valid")}, id => ${cryptoPhotoSession.get("id")}, has_token => ${cryptoPhotoSession.get("token")}")

    if (!cryptoPhotoSession.is("valid")) {
      println(s"CryptoPhoto session not established!%nERROR: ${cryptoPhotoSession.get("error")}, ${cryptoPhotoSession.get("signature")}")
      (None, false, Some(cryptoPhotoSession.get("error")))
    } else {
      (Some(cryptoPhotoSession.get("id")), cryptoPhotoSession.get("token").toBoolean, None)
    }

  }


  def verify(crypto: Crypto) =  {
    val verified: CryptoPhotoUtils.CryptoPhotoResponse  = cryptoPhoto.verify(crypto.token_selector, crypto.token_response_field_row,
      crypto.token_response_field_col, crypto.cp_phc, crypto.email, ip)

    if (!verified.is("valid")) {
      println(s"CryptoPhoto verified!%nERROR: ${verified.get("error")}, ${verified.get("signature")}")
      Some(verified.get("error"))
    } else {
      None
    }
  }
}

object CryptoPhotoConnector extends CryptoPhotoConnector {

}
