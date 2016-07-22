package models

import play.api.libs.json.Json

case class Crypto(email: String, token_selector: String, cp_phc: String, token_response_field_col: String, token_response_field_row: String)

object Crypto {
  implicit val format = Json.format[Crypto]
}
